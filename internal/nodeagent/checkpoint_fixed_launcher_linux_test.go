//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"vram-governor/internal/wsproto"
)

const ownedStopCPUWorkerEnv = "VRAM_GOVERNOR_OWNED_STOP_CPU_FIXTURE"
const ownedStopFixtureRootEnv = "VRAM_GOVERNOR_OWNED_STOP_FIXTURE_ROOT"
const ownedStopG1FixtureEnv = "VRAM_GOVERNOR_OWNED_STOP_G1_FIXTURE"
const ownedStopFixtureRuntimeVersion = "0.3.0-dev (build 1, commit 62acc89), GNU 13.3.0 Linux x86_64"
const ownedStopFixtureRuntimeVersionOutput = "version: 0.3.0-dev (build 1, commit 62acc89)\nbuilt with GNU 13.3.0 for Linux x86_64\n"

var ownedStopWorkerMapping []byte

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		_, _ = io.WriteString(os.Stdout, ownedStopFixtureRuntimeVersionOutput)
		os.Exit(0)
	}
	if os.Getenv(ownedStopCPUWorkerEnv) == "1" {
		os.Exit(runOwnedStopCPUWorker())
	}
	os.Exit(m.Run())
}

func runOwnedStopCPUWorker() int {
	model := os.NewFile(4, "owned-stop-controlled-model")
	if model == nil {
		return 31
	}
	info, err := model.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return 32
	}
	ownedStopWorkerMapping, err = syscall.Mmap(4, 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil || len(ownedStopWorkerMapping) != int(info.Size()) {
		return 33
	}
	address := os.Getenv("CHECKPOINT_CUSTODY_ENDPOINT")
	alias := os.Getenv("CHECKPOINT_CUSTODY_ALIAS")
	if address == "" || alias == "" {
		return 34
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return 35
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"object":"list","data":[{"id":%q,"aliases":[%q],"tags":[],"object":"model","created":1,"owned_by":"llamacpp","meta":{"vocab_type":1,"n_vocab":32000,"n_ctx":4096,"n_ctx_train":4096,"n_embd":128,"n_params":1000000,"size":1024,"ftype":"fixture"}}]}`, alias, alias)
	})}
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return 0
	}
	return 36
}

const ownedStopKernelFixtureMaxFileBytes = 1 << 20

func writeOwnedStopKernelFixtureFile(path string, body []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(body) <= 0 || len(body) > ownedStopKernelFixtureMaxFileBytes || mode.Perm() != 0o640 {
		return errors.New("private owned-stop fixture file request is invalid")
	}
	parentPath := filepath.Dir(path)
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("private owned-stop fixture parent is unavailable")
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentStat.Uid != 0 || parentStat.Gid != 0 || parentInfo.Mode().Perm()&0o022 != 0 {
		return errors.New("private owned-stop fixture parent ownership or mode is unsafe")
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	heldParentInfo, err := parent.Stat()
	if err != nil || !os.SameFile(parentInfo, heldParentInfo) {
		return errors.New("private owned-stop fixture parent changed while opening")
	}
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(path), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("private owned-stop fixture file descriptor is unavailable")
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return err
	}
	checkFile := func(info os.FileInfo, expectedSize int64) error {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode.Perm() || info.Size() != expectedSize || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
			return errors.New("private owned-stop fixture file ownership, mode, type, link count, or size is invalid")
		}
		return nil
	}
	initialInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if err := checkFile(initialInfo, 0); err != nil {
		return err
	}
	written, err := io.Copy(file, bytes.NewReader(body))
	if err != nil || written != int64(len(body)) {
		return errors.New("private owned-stop fixture file write was incomplete")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	finalInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if err := checkFile(finalInfo, int64(len(body))); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	if err := parent.Sync(); err != nil {
		return err
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(finalInfo, pathInfo) {
		return errors.New("private owned-stop fixture pathname no longer names the held file")
	}
	if err := checkFile(pathInfo, int64(len(body))); err != nil {
		return err
	}
	currentParent, err := os.Lstat(parentPath)
	if err != nil || !currentParent.IsDir() || currentParent.Mode()&os.ModeSymlink != 0 || !os.SameFile(parentInfo, currentParent) {
		return errors.New("private owned-stop fixture parent changed after file publication")
	}
	currentParentStat, ok := currentParent.Sys().(*syscall.Stat_t)
	if !ok || currentParentStat.Uid != 0 || currentParentStat.Gid != 0 || currentParent.Mode().Perm()&0o022 != 0 {
		return errors.New("private owned-stop fixture parent ownership or mode changed after publication")
	}
	return nil
}

func makeOwnedStopKernelFixture(base, modelPath string) (checkpointOwnedStopPaths, *Config, string, CheckpointLaunchPlan, string, string, string, ed25519.PublicKey, ed25519.PrivateKey, error) {
	var paths checkpointOwnedStopPaths
	modelSHA, modelBytes, err := fileDigest(modelPath)
	if err != nil || modelBytes <= 0 {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, errors.New("reviewed fs-verity model image is unavailable")
	}
	executable, err := os.Executable()
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	executableSHA, _, err := fileDigest(executable)
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	endpointProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	port := endpointProbe.Addr().(*net.TCPAddr).Port
	if err := endpointProbe.Close(); err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	for _, dir := range []string{"config", "trusted", "state", "custody", "snapshots", "private", "public", "public/receipts", "socket"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o700); err != nil {
			return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
		}
	}
	paths = checkpointOwnedStopPaths{
		NodeConfig: filepath.Join(base, "config", "node-agent.yaml"), NodeEnv: filepath.Join(base, "config", "node-agent.env"),
		NodeState: filepath.Join(base, "state", "command-state.json"), Socket: filepath.Join(base, "socket", "stop.sock"),
		PrivateKey: filepath.Join(base, "private", "ed25519.key"), PublicKey: filepath.Join(base, "public", "ed25519.pub"),
		ReceiptDir: filepath.Join(base, "public", "receipts"), SnapshotRoot: filepath.Join(base, "snapshots"),
		TrustedRoot: base, ConfigRoot: filepath.Join(base, "config"), StateDir: filepath.Join(base, "state"),
		NodeUID: 0, NodeGID: 0, principalPinned: true,
	}
	secret := strings.Repeat("S", 48)
	cfg := &Config{NodeID: "owned-stop-node", CommandSigningSecret: secret, CommandSigningSecretEnv: "VRAM_NODE_COMMAND_SECRET", CommandStatePath: paths.NodeState,
		LlamaCPP: struct {
			Servers []LlamaCPPServerConfig `yaml:"servers"`
		}{Servers: []LlamaCPPServerConfig{{ID: "server", Endpoint: "http://127.0.0.1:" + strconv.Itoa(port)}}}}
	configBytes, err := yaml.Marshal(struct {
		NodeID                  string `yaml:"node_id"`
		CommandSigningSecret    string `yaml:"command_signing_secret"`
		CommandSigningSecretEnv string `yaml:"command_signing_secret_env"`
		CommandStatePath        string `yaml:"command_state_path"`
		LlamaCPP                struct {
			Servers []LlamaCPPServerConfig `yaml:"servers"`
		} `yaml:"llamacpp"`
	}{NodeID: cfg.NodeID, CommandSigningSecretEnv: cfg.CommandSigningSecretEnv, CommandStatePath: paths.NodeState, LlamaCPP: cfg.LlamaCPP})
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	if err := writeOwnedStopKernelFixtureFile(paths.NodeConfig, configBytes, 0o640); err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, fmt.Errorf("write exact-mode private node config fixture: %w", err)
	}
	if err := writeOwnedStopKernelFixtureFile(paths.NodeEnv, []byte("VRAM_NODE_TOKEN="+strings.Repeat("T", 32)+"\nVRAM_NODE_COMMAND_SECRET="+secret+"\n"), 0o640); err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, fmt.Errorf("write exact-mode private node environment fixture: %w", err)
	}
	snapshotName := "owned-stop-fixture.kv"
	snapshotBytes := []byte("private owned-stop snapshot fixture\n")
	if err := os.WriteFile(filepath.Join(paths.SnapshotRoot, snapshotName), snapshotBytes, 0o600); err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	snapshotDigest := sha256Hex(snapshotBytes)
	plan := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Alias: "owned-stop-fixture", Model: CheckpointLaunchModel{Path: modelPath, SHA256: modelSHA, Bytes: modelBytes},
		Executable: CheckpointLaunchExecutable{Path: executable, SHA256: executableSHA}, Endpoint: CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port},
		TotalContextTokens: 4096, ParallelSlots: 1, SnapshotRoot: paths.SnapshotRoot,
		Custody:   CheckpointLaunchCustodyQuotas{Root: filepath.Join(base, "custody"), MaxArtifactBytes: modelBytes, MaxStagingBytes: 48 << 20, ReserveBytes: 1 << 20},
		Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: ownedStopFixtureRuntimeVersion, MaxAccelerators: 1, OffloadPolicy: "full_gpu", MinGPUBytes: 1, MaxHostRSSBytes: 1 << 30}}
	planBytes, err := json.Marshal(plan)
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	planPath := filepath.Join(base, "trusted", "launch-plan.json")
	if err := writeOwnedStopKernelFixtureFile(planPath, planBytes, 0o640); err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, fmt.Errorf("write exact-mode private launch plan fixture: %w", err)
	}
	private, public, err := ensureCheckpointOwnedStopKeysAt(paths)
	if err != nil {
		return paths, nil, "", CheckpointLaunchPlan{}, "", "", "", nil, nil, err
	}
	return paths, cfg, planPath, plan, snapshotName, snapshotDigest, secret, public, private, nil
}

func openOwnedStopFixturePlan(path, fixtureRoot string, expectedRoot os.FileInfo) (*PinnedCheckpointLaunchPlan, error) {
	if expectedRoot == nil {
		return nil, errors.New("owned-stop fixture root identity pin is required")
	}
	root, err := filepath.Abs(fixtureRoot)
	if err != nil || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("owned-stop plan fixture root is not canonical")
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil || resolvedRoot != root {
		return nil, errors.New("owned-stop fixture root is missing or traverses a symlink")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(expectedRoot, rootInfo) {
		return nil, errors.New("owned-stop fixture root no longer matches the exact created directory")
	}
	if err := validateCanonicalPathSyntax(path); err != nil {
		return nil, err
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, errors.New("owned-stop fixture plan path is not canonical")
	}
	relative, err := filepath.Rel(root, canonical)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, errors.New("owned-stop fixture plan escaped its private root")
	}
	parents, err := ownedStopFixturePlanParents(root, filepath.Dir(canonical), expectedRoot)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(canonical, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open held owned-stop fixture plan: %w", err)
	}
	f := os.NewFile(uintptr(fd), canonical)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("held owned-stop fixture plan descriptor is unavailable")
	}
	ok := false
	defer func() {
		if !ok {
			_ = f.Close()
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	dev, ino, size, uid, mode, nlink, err := launchStat(info)
	if err != nil || !info.Mode().IsRegular() || uid != 0 || nlink != 1 || mode&0022 != 0 || size < 1 || size > checkpointLaunchPlanMaxBytes {
		return nil, errors.New("owned-stop fixture plan inode ownership, mode, type, links, or size is unsafe")
	}
	ctx := context.Background()
	raw, err := readPinnedLaunchBytes(ctx, f, size)
	if err != nil || int64(len(raw)) != size {
		return nil, errors.New("owned-stop fixture plan could not be completely read from its held descriptor")
	}
	if err := verifyLaunchPathIdentity(canonical, dev, ino, size, 0); err != nil {
		return nil, err
	}
	if err := verifyCheckpointLaunchParents(parents, 0); err != nil {
		return nil, err
	}
	plan, err := ParseCheckpointLaunchPlan(raw)
	if err != nil {
		return nil, err
	}
	args, err := fixedCheckpointPlacementArguments(plan)
	if err != nil {
		return nil, err
	}
	if err := verifyCheckpointLaunchParents(parents, 0); err != nil {
		return nil, err
	}
	ok = true
	return &PinnedCheckpointLaunchPlan{plan: plan, args: args, path: canonical, file: f, device: dev, inode: ino, expectedUID: 0, size: size, contentSHA256: sha256.Sum256(raw), parents: parents}, nil
}

func ownedStopFixturePlanParents(root, planParent string, expectedRoot os.FileInfo) ([]checkpointLaunchParent, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || !filepath.IsAbs(planParent) || filepath.Clean(planParent) != planParent {
		return nil, errors.New("owned-stop fixture plan parent chain is not canonical")
	}
	relative, err := filepath.Rel(root, planParent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, errors.New("owned-stop fixture plan parent escaped its exact private root")
	}
	paths := []string{root}
	if relative != "." {
		current := root
		for _, component := range strings.Split(relative, string(os.PathSeparator)) {
			if component == "" || component == "." || component == ".." {
				return nil, errors.New("owned-stop fixture plan parent contains an invalid component")
			}
			current = filepath.Join(current, component)
			paths = append(paths, current)
		}
	}
	pins := make([]checkpointLaunchParent, 0, len(paths))
	for _, path := range paths {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return nil, errors.New("owned-stop fixture plan parent is missing or traverses a symlink")
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("owned-stop fixture plan parent is not a real directory")
		}
		if path == root && !os.SameFile(expectedRoot, info) {
			return nil, errors.New("owned-stop fixture root was substituted during plan pinning")
		}
		dev, ino, _, uid, mode, _, err := launchStat(info)
		if err != nil || uid != 0 || mode&0022 != 0 {
			return nil, errors.New("owned-stop fixture plan parent is not root-owned and non-writable")
		}
		pins = append(pins, checkpointLaunchParent{path: path, device: dev, inode: ino, uid: uid, mode: mode})
	}
	return pins, nil
}

func fileDigest(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, 1<<34))
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func ownedStopProcessCgroup(ctx context.Context, pid int) (string, error) {
	if pid <= 1 {
		return "", errors.New("invalid worker PID")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "0::") {
			group := strings.TrimPrefix(line, "0::")
			if !validCheckpointCgroupPath(group) {
				return "", errors.New("worker has invalid unified cgroup")
			}
			return group, nil
		}
	}
	return "", errors.New("worker unified cgroup is unavailable")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func (s *checkpointOwnedStopServer) ackIsDone() bool {
	if s == nil || s.ackDone == nil {
		return false
	}
	select {
	case <-s.ackDone:
		return true
	default:
		return false
	}
}

func ownedStopFixtureLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func ownedStopFixtureProcessor(cfg *Config, paths checkpointOwnedStopPaths, planPath string, rootPin os.FileInfo) (*commandProcessor, error) {
	p := newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	p.ownedStopPaths = paths
	p.ownedStopPlanPath = planPath
	p.openOwnedStopPlan = func(ctx context.Context, path string) (*PinnedCheckpointLaunchPlan, error) {
		if path != planPath {
			return nil, errors.New("fixture plan path drift")
		}
		return openOwnedStopFixturePlan(path, filepath.Dir(filepath.Dir(path)), rootPin)
	}
	if p.initError != nil {
		return nil, p.initError
	}
	return p, nil
}

func observeOwnedStopKernelManagedBinding(ctx context.Context, planPath, fixtureRoot string, rootPin os.FileInfo, spec CheckpointLaunchPlan, store *CheckpointCustodyStore, verification CheckpointCustodyVerification, workerPID int, invocation, cgroup string) (CheckpointManagedBinding, error) {
	unitSource := checkpointUnitLinuxSource{procRoot: "/proc", collect: func(callCtx context.Context, expected int) (checkpointUnitObservation, error) {
		if err := callCtx.Err(); err != nil {
			return checkpointUnitObservation{}, err
		}
		if expected > 0 && expected != workerPID {
			return checkpointUnitObservation{}, errors.New("unit MainPID drift")
		}
		members, err := readCheckpointCgroupMembership(callCtx, filepath.Join("/proc", strconv.Itoa(workerPID), "cgroup"), cgroup)
		if err != nil {
			return checkpointUnitObservation{}, err
		}
		return checkpointUnitObservation{MainPID: workerPID, InvocationID: invocation, ControlGroup: cgroup, ActiveState: "active", SubState: "running", CgroupMembers: members}, nil
	}}
	return observeCheckpointManagedBindingLinux(ctx, checkpointManagedObservationSource{
		openPlan: func(callCtx context.Context) (*PinnedCheckpointLaunchPlan, error) {
			return openOwnedStopFixturePlan(planPath, fixtureRoot, rootPin)
		},
		validatePlan: func(pin *PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error) {
			plan := pin.Spec()
			if plan.Version != checkpointLaunchPlanVersion2 || plan.Placement == nil || !reflect.DeepEqual(plan, spec) {
				return CheckpointLaunchPlan{}, errors.New("private v2 plan differs from the fixture-approved spec")
			}
			return plan, nil
		},
		openStore: func(plan CheckpointLaunchPlan) (*CheckpointCustodyStore, error) {
			if plan.Custody.Root != spec.Custody.Root {
				return nil, errors.New("private custody root drift")
			}
			return store, nil
		},
		associate: func(callCtx context.Context, custody *CheckpointCustodyStore, plan CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
			modelRoot := filepath.Dir(verification.ArtifactPath)
			req := CheckpointUnitIdentityRequest{Custody: custody, ExpectedAlias: plan.Alias, Identity: CheckpointIdentityRequest{Endpoint: managedCheckpointEndpoint(plan), ServiceUnit: checkpointIdentityServiceUnit, ModelPath: verification.ArtifactPath, ExpectedModelSHA256: plan.Model.SHA256, ApprovedModelRoots: []string{modelRoot}, ExpectedExecutableSHA256: plan.Executable.SHA256}}
			return observeCheckpointManagedUnitLinux(callCtx, req, unitSource)
		},
		alias: observeCheckpointManagedAlias,
		placement: func(_ context.Context, plan CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
			return CheckpointDevicePlacement{Backend: plan.Placement.Backend, PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
		},
		namespaceRoute: func(context.Context, int) (bool, error) { return false, nil },
		footprint: func(_ context.Context, pid int, _ uint64, placement CheckpointDevicePlacement) (int64, int64, error) {
			if pid != workerPID || placement.PhysicalIdentity != spec.Placement.PhysicalIdentity {
				return 0, 0, errors.New("fixture process or physical device drift")
			}
			return spec.Placement.MinGPUBytes, 1 << 20, nil
		},
		readArgv: readManagedCheckpointArgv,
	})
}

func ownedStopFixtureCommand(nodeID, binding, snapshotName, snapshotDigest, epoch, secret string) (wsproto.CommandPayload, error) {
	now := time.Now().UTC()
	command := wsproto.CommandPayload{ID: "owned-stop-victim", IdempotencyKey: "owned-stop-victim-key", NodeID: nodeID, Command: "llm_displacement_stop", IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), Args: map[string]any{
		"operation_id": "owned-stop-operation", "step_id": "victim_stop", "target_kind": "llamacpp", "target_id": nodeID + "-server", "accelerator_id": "GPU-01234567-89ab-cdef-0123-456789abcdef",
		"workload_id": "owned-stop-workload", "workload_revision": int64(1), "model": "owned-stop/model", "model_alias": "owned-stop-fixture", "local_checkpoint_binding": "sha256:" + binding,
		"snapshot_name": snapshotName, "snapshot_digest": snapshotDigest, "recovery_epoch": epoch, "fencing_token": int64(41),
	}}
	var err error
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	return command, err
}

func TestOwnedStopHandlePersistsSignedOriginalBeforeIPC(t *testing.T) {
	if os.Getenv(ownedStopG1FixtureEnv) == "" {
		return
	}
	if os.Getenv(ownedStopG1FixtureEnv) != "1" {
		t.Fatal("G1 durable fixture opt-in is malformed")
	}
	if os.Geteuid() != 0 {
		t.Fatal("private durable owned-stop fixture requires the local root test principal")
	}
	fixture, err := os.MkdirTemp("/run", "vram-owned-stop-g1-")
	if err != nil {
		t.Fatal(err)
	}
	var fixtureInfo os.FileInfo
	defer func() {
		if fixtureInfo == nil {
			t.Errorf("G1 fixture identity was unavailable; preserving private path %q", fixture)
			return
		}
		current, statErr := os.Lstat(fixture)
		if errors.Is(statErr, os.ErrNotExist) {
			return
		}
		if statErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(fixtureInfo, current) || filepath.Dir(fixture) != "/run" || !strings.HasPrefix(filepath.Base(fixture), "vram-owned-stop-g1-") {
			t.Errorf("G1 fixture identity changed; preserving private path %q", fixture)
			return
		}
		if removeErr := os.RemoveAll(fixture); removeErr != nil {
			t.Errorf("remove exact private G1 fixture: %v", removeErr)
			return
		}
		if _, verifyErr := os.Lstat(fixture); !errors.Is(verifyErr, os.ErrNotExist) {
			t.Errorf("exact private G1 fixture remains after cleanup: %v", verifyErr)
		}
	}()
	fixtureInfo, err = os.Lstat(fixture)
	if err != nil || !fixtureInfo.IsDir() || fixtureInfo.Mode()&os.ModeSymlink != 0 || fixtureInfo.Mode().Perm() != 0o700 {
		t.Fatal("private G1 fixture directory identity or permissions are unsafe")
	}
	paths := checkpointOwnedStopPaths{
		NodeConfig: filepath.Join(fixture, "config", "node-agent.yaml"), NodeEnv: filepath.Join(fixture, "config", "node-agent.env"),
		NodeState: filepath.Join(fixture, "state", "command-state.json"), Socket: filepath.Join(fixture, "ipc", "stop.sock"),
		PrivateKey: filepath.Join(fixture, "private", "ed25519.key"), PublicKey: filepath.Join(fixture, "public", "ed25519.pub"),
		ReceiptDir: filepath.Join(fixture, "public", "receipts"), SnapshotRoot: filepath.Join(fixture, "snapshots"),
		TrustedRoot: "/run", ConfigRoot: filepath.Join(fixture, "config"), StateDir: filepath.Join(fixture, "state"),
		NodeUID: 0, NodeGID: 0, principalPinned: true,
	}
	for _, dir := range []string{filepath.Dir(paths.NodeConfig), filepath.Dir(paths.NodeState), filepath.Dir(paths.Socket), filepath.Dir(paths.SnapshotRoot)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := strings.Repeat("G", 48)
	cfg := &Config{NodeID: "owned-stop-g1-node", CommandSigningSecret: secret, CommandSigningSecretEnv: "VRAM_NODE_COMMAND_SECRET", CommandStatePath: paths.NodeState}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "server", Endpoint: "http://127.0.0.1:1"}}
	configBytes, err := yaml.Marshal(struct {
		NodeID                  string `yaml:"node_id"`
		CommandSigningSecret    string `yaml:"command_signing_secret"`
		CommandSigningSecretEnv string `yaml:"command_signing_secret_env"`
		CommandStatePath        string `yaml:"command_state_path"`
		LlamaCPP                struct {
			Servers []LlamaCPPServerConfig `yaml:"servers"`
		} `yaml:"llamacpp"`
	}{NodeID: cfg.NodeID, CommandSigningSecretEnv: cfg.CommandSigningSecretEnv, CommandStatePath: cfg.CommandStatePath, LlamaCPP: cfg.LlamaCPP})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.NodeConfig, configBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.NodeEnv, []byte("VRAM_NODE_TOKEN="+strings.Repeat("T", 32)+"\nVRAM_NODE_COMMAND_SECRET="+secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(paths.SnapshotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	snapshot := []byte("G1 private snapshot fixture\n")
	if err := os.WriteFile(filepath.Join(paths.SnapshotRoot, "victim.kv"), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	private, public, err := ensureCheckpointOwnedStopKeysAt(paths)
	if err != nil || len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize {
		t.Fatalf("root stop key fixture setup failed: %v", err)
	}
	planSpec := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Alias: "owned-stop-fixture", Placement: &CheckpointLaunchPlacement{PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef"}}
	planPath := filepath.Join(fixture, "trusted", "plan.json")
	if err := os.MkdirAll(filepath.Dir(planPath), 0o700); err != nil {
		t.Fatal(err)
	}
	processor := newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	processor.ownedStopPaths, processor.ownedStopPlanPath = paths, planPath
	processor.openOwnedStopPlan = func(_ context.Context, requested string) (*PinnedCheckpointLaunchPlan, error) {
		if requested != planPath {
			return nil, errors.New("private G1 fixed-plan selector changed")
		}
		return &PinnedCheckpointLaunchPlan{plan: planSpec}, nil
	}
	processor.recoveryEpoch = "g1-durable-epoch"
	if err := processor.save(); err != nil {
		t.Fatal(err)
	}
	processor = newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	processor.ownedStopPaths, processor.ownedStopPlanPath = paths, planPath
	processor.openOwnedStopPlan = func(_ context.Context, requested string) (*PinnedCheckpointLaunchPlan, error) {
		if requested != planPath {
			return nil, errors.New("private G1 fixed-plan selector changed")
		}
		return &PinnedCheckpointLaunchPlan{plan: planSpec}, nil
	}
	if processor.recoveryEpoch != "g1-durable-epoch" || processor.initError != nil {
		t.Fatalf("baseline durable recovery epoch did not reload: epoch=%q error=%v", processor.recoveryEpoch, processor.initError)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	ipcDone := make(chan struct{})
	defer func() {
		_ = listener.Close()
		select {
		case <-ipcDone:
		case <-time.After(time.Second):
			t.Error("fake IPC receiver did not stop after listener close")
		}
	}()
	if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	fixtureCtx, fixtureCancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer fixtureCancel()
	configDigest := sha256Hex(configBytes)
	ipcObserved := make(chan error, 1)
	go func() {
		defer close(ipcDone)
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			ipcObserved <- acceptErr
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
			ipcObserved <- err
			return
		}
		var request ownedStopRequest
		if decodeErr := json.NewDecoder(io.LimitReader(conn, checkpointOwnedStopMaxFrame+1)).Decode(&request); decodeErr != nil {
			ipcObserved <- decodeErr
			return
		}
		_, original, pending, verifyErr := verifyOwnedStopNodeIntentAt(fixtureCtx, request, configDigest, paths)
		if verifyErr == nil {
			wire, wireErr := wsproto.CanonicalCommandEnvelope(original)
			material, materialErr := wsproto.CommandSigningMaterialForOwnedStop(original)
			fresh := newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
			if wireErr != nil || materialErr != nil || !bytes.Equal(wire, request.Command) || !bytes.Equal(pending.OriginalEnvelope, wire) || pending.SigningMaterialSHA256 != sha256Hex(material) || pending.StopRecoveryEpoch != "g1-durable-epoch" || !bytes.Equal(pending.PinnedRootStopPublicKey, public) || fresh.initError != nil || !bytes.Equal(fresh.pending[original.ID].OriginalEnvelope, wire) || fresh.fences[ownedStopFenceKey(fmt.Sprint(original.Args["accelerator_id"]))] != int64FromArg(original.Args["fencing_token"]) {
				verifyErr = errors.New("freshly reloaded command state did not preserve the exact signed envelope, digest, key pin, epoch, and accelerator fence")
			}
		}
		ipcObserved <- verifyErr
		_ = json.NewEncoder(conn).Encode(ownedStopReply{Error: "fixture stops after verifying the durable write-ahead intent"})
	}()
	badSignature, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), processor.recoveryEpoch, secret)
	if err != nil {
		t.Fatal(err)
	}
	badSignature.Signature = strings.Repeat("0", len(badSignature.Signature))
	if result := processor.Handle(fixtureCtx, badSignature); result.OK || result.Uncertain {
		t.Fatalf("invalid signature reached the external boundary: %+v", result)
	}
	wrongNode := badSignature
	wrongNode.ID, wrongNode.IdempotencyKey, wrongNode.Signature = "wrong-node", "wrong-node-key", ""
	wrongNode.NodeID = "different-node"
	wrongNode.Signature, err = wsproto.SignCommand(wrongNode, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if result := processor.Handle(fixtureCtx, wrongNode); result.OK || result.Uncertain {
		t.Fatalf("wrong-node signature reached the external boundary: %+v", result)
	}
	wrongConfiguredTarget, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), processor.recoveryEpoch, secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongConfiguredTarget.ID, wrongConfiguredTarget.IdempotencyKey = "g1-unconfigured-target", "g1-unconfigured-target-key"
	wrongConfiguredTarget.Args["target_id"] = cfg.NodeID + "-unconfigured"
	wrongConfiguredTarget.Signature, err = wsproto.SignCommand(wrongConfiguredTarget, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if result := processor.Handle(fixtureCtx, wrongConfiguredTarget); result.OK || result.Uncertain {
		t.Fatalf("syntactically qualified but unconfigured target reached IPC: %+v", result)
	}
	if _, pending := processor.pending[wrongConfiguredTarget.ID]; pending {
		t.Fatal("unconfigured node-qualified target created a durable intent before IPC")
	}
	wrongAlias, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), processor.recoveryEpoch, secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongAlias.Args["model_alias"] = "unrelated-alias"
	wrongAlias.Signature, err = wsproto.SignCommand(wrongAlias, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if result := processor.Handle(fixtureCtx, wrongAlias); result.OK || result.Uncertain {
		t.Fatalf("wrong model alias reached the external boundary: %+v", result)
	}
	wrongEpoch, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), "different-epoch", secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongEpoch.ID, wrongEpoch.IdempotencyKey = "g1-wrong-epoch", "g1-wrong-epoch-key"
	wrongEpoch.Signature, err = wsproto.SignCommand(wrongEpoch, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if result := processor.Handle(fixtureCtx, wrongEpoch); result.OK || result.Uncertain {
		t.Fatalf("wrong recovery epoch reached the external boundary: %+v", result)
	}
	command, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), processor.recoveryEpoch, secret)
	if err != nil {
		t.Fatal(err)
	}
	command.ID, command.IdempotencyKey = "g1-persist-before-ipc", "g1-persist-before-ipc-key"
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	result := processor.Handle(fixtureCtx, command)
	if result.OK || !result.Uncertain {
		t.Fatalf("deliberate fake-IPC lost reply did not retain an uncertain durable stop: %+v", result)
	}
	if verifyErr := <-ipcObserved; verifyErr != nil {
		t.Fatalf("fake IPC observed no independently authenticated fsynced original intent: %v", verifyErr)
	}
	stateBytes, err := os.ReadFile(paths.NodeState)
	if err != nil {
		t.Fatal(err)
	}
	var driftEnvelope commandStateEnvelope
	if err := json.Unmarshal(stateBytes, &driftEnvelope); err != nil {
		t.Fatal(err)
	}
	driftPending, exists := driftEnvelope.State.Pending[command.ID]
	if !exists {
		t.Fatal("write-ahead pending state disappeared before drift control")
	}
	driftPending.SigningMaterialSHA256 = strings.Repeat("f", 64)
	driftEnvelope.State.Pending[command.ID] = driftPending
	statePayload, err := json.Marshal(driftEnvelope.State)
	if err != nil {
		t.Fatal(err)
	}
	driftEnvelope.Checksum = sha256Hex(statePayload)
	driftBytes, err := json.MarshalIndent(driftEnvelope, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	driftStateDir := filepath.Join(fixture, "pending-drift-state")
	if err := os.MkdirAll(driftStateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	driftStatePath := filepath.Join(driftStateDir, "command-state.json")
	if err := os.WriteFile(driftStatePath, driftBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	journalBytes, err := os.ReadFile(paths.NodeState + ".journal")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(driftStatePath+".journal", journalBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	driftConfig := *cfg
	driftConfig.CommandStatePath = driftStatePath
	drifted := newCommandProcessor(&driftConfig, ownedStopFixtureLogger(), true)
	drifted.ownedStopPaths, drifted.ownedStopPlanPath = paths, planPath
	if drifted.initError != nil || !drifted.stateBlocked || drifted.stateBlockReason != blockReasonDurability || !drifted.HasPending() || drifted.Ready() {
		t.Fatalf("pending signing-digest drift without its journal anchor was not durably blocked with intent retained: init=%v blocked=%t reason=%q pending=%t ready=%t", drifted.initError, drifted.stateBlocked, drifted.stateBlockReason, drifted.HasPending(), drifted.Ready())
	}
	queryArgs := make(map[string]any, len(command.Args)+5)
	for key, value := range command.Args {
		queryArgs[key] = value
	}
	originalWire := mustCanonicalOwnedStop(t, command)
	queryArgs["original_command_id"] = command.ID
	queryArgs["original_idempotency_key"] = command.IdempotencyKey
	queryArgs["original_envelope_sha256"] = sha256Hex(originalWire)
	queryArgs["expected_fence"] = command.Args["fencing_token"]
	queryArgs["observed_after_fence"] = command.Args["fencing_token"]
	driftQuery := wsproto.CommandPayload{ID: "g1-durable-query", IdempotencyKey: "g1-durable-query-key", NodeID: command.NodeID, Command: "llm_displacement_stop_query", Args: queryArgs, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
	driftQuery.Signature, err = wsproto.SignCommand(driftQuery, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if err := wsproto.ValidateOwnedStopCommandArgs(driftQuery.Command, driftQuery.Args); err != nil || !wsproto.VerifyCommand(driftQuery, []byte(secret)) {
		t.Fatalf("durability control query did not pass the owned-stop schema and HMAC controls: schema=%v", err)
	}
	if _, err := wsproto.CanonicalCommandEnvelope(driftQuery); err != nil {
		t.Fatalf("durability control query is not a canonical signed envelope: %v", err)
	}
	if !drifted.ownedStopQueryMatchesPending(driftQuery) {
		t.Fatal("durability control query does not link to the exact original signed pending stop")
	}
	durablePendingBefore := drifted.pending[command.ID]
	durablePendingBefore.OriginalEnvelope = append([]byte(nil), durablePendingBefore.OriginalEnvelope...)
	durablePendingBefore.PinnedRootStopPublicKey = append([]byte(nil), durablePendingBefore.PinnedRootStopPublicKey...)
	durableFenceKey := ownedStopFenceKey(fmt.Sprint(command.Args["accelerator_id"]))
	durableFenceBefore, durableFenceExists := drifted.fences[durableFenceKey]
	operationJournalBefore, err := json.Marshal(drifted.ownedStopOperations)
	if err != nil {
		t.Fatal(err)
	}
	var driftQueryReachedExternalBoundary bool
	drifted.onExternalWork = func(wsproto.CommandPayload) { driftQueryReachedExternalBoundary = true }
	driftQueryResult := drifted.Handle(fixtureCtx, driftQuery)
	if driftQueryResult.OK || driftQueryResult.Uncertain || driftQueryResult.Error != "command state blocked: "+blockReasonDurability {
		t.Fatalf("exact linked stop query bypassed the durable journal mismatch: %+v", driftQueryResult)
	}
	if driftQueryReachedExternalBoundary || drifted.Ready() || !drifted.HasPending() || !reflect.DeepEqual(drifted.pending[command.ID], durablePendingBefore) {
		t.Fatal("blocked exact stop query crossed an external boundary, changed readiness, or altered the original pending intent")
	}
	if currentFence, exists := drifted.fences[durableFenceKey]; exists != durableFenceExists || currentFence != durableFenceBefore {
		t.Fatal("blocked exact stop query changed the accelerator fence")
	}
	operationJournalAfter, err := json.Marshal(drifted.ownedStopOperations)
	if err != nil || !bytes.Equal(operationJournalAfter, operationJournalBefore) {
		t.Fatalf("blocked exact stop query changed the operation journal: %v", err)
	}
	if _, queryPending := drifted.pending[driftQuery.ID]; queryPending {
		t.Fatal("read-only durable-stop query created a pending mutation")
	}
	drifted.initError = errors.New("fixture command-state initialization failure")
	initErrorQueryResult := drifted.Handle(fixtureCtx, driftQuery)
	drifted.initError = nil
	if initErrorQueryResult.OK || initErrorQueryResult.Uncertain || initErrorQueryResult.Error != "command state initialization failed" || driftQueryReachedExternalBoundary || !drifted.HasPending() || drifted.Ready() {
		t.Fatalf("exact linked stop query bypassed a command-state initialization failure: result=%+v external=%t pending=%t ready=%t", initErrorQueryResult, driftQueryReachedExternalBoundary, drifted.HasPending(), drifted.Ready())
	}
	driftAttempt := command
	driftAttempt.ID, driftAttempt.IdempotencyKey = "g1-pending-drift", "g1-pending-drift-key"
	driftAttempt.Signature, err = wsproto.SignCommand(driftAttempt, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	var driftReachedExternalBoundary bool
	drifted.onExternalWork = func(wsproto.CommandPayload) { driftReachedExternalBoundary = true }
	if result := drifted.Handle(fixtureCtx, driftAttempt); result.OK || result.Uncertain {
		t.Fatalf("drifted pending/journal state reached an external-effect boundary: %+v", result)
	}
	if driftReachedExternalBoundary || drifted.Ready() {
		t.Fatal("drifted pending/journal state crossed the external-work boundary or became ready")
	}
	if _, exists := drifted.pending[driftAttempt.ID]; exists {
		t.Fatal("drift attempt created a new intent despite the durable journal mismatch")
	}
	restarted := newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	if restarted.initError != nil || !bytes.Equal(restarted.pending[command.ID].OriginalEnvelope, mustCanonicalOwnedStop(t, command)) || restarted.pending[command.ID].SigningMaterialSHA256 == "" || restarted.pending[command.ID].StopRecoveryEpoch != "g1-durable-epoch" {
		t.Fatal("lost IPC reply did not survive a fresh durable command-state reload")
	}
	fmt.Println("__OWNED_STOP_G1_FIXTURE_POSITIVE__")
}

func mustCanonicalOwnedStop(t *testing.T, command wsproto.CommandPayload) []byte {
	t.Helper()
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestOwnedStopHandleDirectVictimUrgentSameProcess(t *testing.T) {
	if os.Getenv(ownedStopG1FixtureEnv) == "" {
		return
	}
	if os.Getenv(ownedStopG1FixtureEnv) != "1" || os.Geteuid() != 0 {
		t.Fatal("direct G1 fixture requires its explicit local root opt-in")
	}
	fixture, err := os.MkdirTemp("/run", "vram-owned-stop-direct-")
	if err != nil {
		t.Fatal(err)
	}
	var fixtureInfo os.FileInfo
	defer func() {
		if fixtureInfo == nil {
			t.Errorf("direct G1 fixture identity unavailable; preserving %q", fixture)
			return
		}
		current, statErr := os.Lstat(fixture)
		if errors.Is(statErr, os.ErrNotExist) {
			return
		}
		if statErr != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || !os.SameFile(fixtureInfo, current) || filepath.Dir(fixture) != "/run" || !strings.HasPrefix(filepath.Base(fixture), "vram-owned-stop-direct-") {
			t.Errorf("direct G1 fixture identity changed; preserving %q", fixture)
			return
		}
		if removeErr := os.RemoveAll(fixture); removeErr != nil {
			t.Errorf("remove exact direct G1 fixture: %v", removeErr)
			return
		}
		if _, verifyErr := os.Lstat(fixture); !errors.Is(verifyErr, os.ErrNotExist) {
			t.Errorf("direct G1 fixture remains after cleanup: %v", verifyErr)
		}
	}()
	fixtureInfo, err = os.Lstat(fixture)
	if err != nil || !fixtureInfo.IsDir() || fixtureInfo.Mode()&os.ModeSymlink != 0 || fixtureInfo.Mode().Perm() != 0o700 {
		t.Fatal("direct G1 private directory is not pinned and mode 0700")
	}
	paths := checkpointOwnedStopPaths{
		NodeConfig: filepath.Join(fixture, "config", "node-agent.yaml"), NodeEnv: filepath.Join(fixture, "config", "node-agent.env"),
		NodeState: filepath.Join(fixture, "state", "command-state.json"), Socket: filepath.Join(fixture, "ipc", "stop.sock"),
		PrivateKey: filepath.Join(fixture, "private", "ed25519.key"), PublicKey: filepath.Join(fixture, "public", "ed25519.pub"),
		ReceiptDir: filepath.Join(fixture, "public", "receipts"), SnapshotRoot: filepath.Join(fixture, "snapshots"),
		TrustedRoot: "/run", ConfigRoot: filepath.Join(fixture, "config"), StateDir: filepath.Join(fixture, "state"),
		NodeUID: 0, NodeGID: 0, principalPinned: true,
	}
	for _, dir := range []string{filepath.Dir(paths.NodeConfig), filepath.Dir(paths.NodeState), filepath.Dir(paths.Socket), paths.SnapshotRoot} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := strings.Repeat("R", 48)
	cfg := &Config{NodeID: "owned-stop-direct-node", CommandSigningSecret: secret, CommandSigningSecretEnv: "VRAM_NODE_COMMAND_SECRET", CommandStatePath: paths.NodeState}
	cfg.LlamaCPP.Servers = []LlamaCPPServerConfig{{ID: "server", Endpoint: "http://127.0.0.1:1"}}
	configBytes, err := yaml.Marshal(struct {
		NodeID                  string `yaml:"node_id"`
		CommandSigningSecret    string `yaml:"command_signing_secret"`
		CommandSigningSecretEnv string `yaml:"command_signing_secret_env"`
		CommandStatePath        string `yaml:"command_state_path"`
		LlamaCPP                struct {
			Servers []LlamaCPPServerConfig `yaml:"servers"`
		} `yaml:"llamacpp"`
	}{NodeID: cfg.NodeID, CommandSigningSecretEnv: cfg.CommandSigningSecretEnv, CommandStatePath: cfg.CommandStatePath, LlamaCPP: cfg.LlamaCPP})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.NodeConfig, configBytes, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.NodeEnv, []byte("VRAM_NODE_TOKEN="+strings.Repeat("T", 32)+"\nVRAM_NODE_COMMAND_SECRET="+secret+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	snapshot := []byte("direct victim-to-urgent G1 snapshot\n")
	if err := os.WriteFile(filepath.Join(paths.SnapshotRoot, "victim.kv"), snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	private, public, err := ensureCheckpointOwnedStopKeysAt(paths)
	if err != nil {
		t.Fatal(err)
	}
	planSpec := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Alias: "owned-stop-fixture", Placement: &CheckpointLaunchPlacement{PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef"}}
	planPath := filepath.Join(fixture, "trusted", "plan.json")
	processor := newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	processor.ownedStopPaths, processor.ownedStopPlanPath = paths, planPath
	processor.openOwnedStopPlan = func(_ context.Context, requested string) (*PinnedCheckpointLaunchPlan, error) {
		if requested != planPath {
			return nil, errors.New("direct G1 fixed plan selector drift")
		}
		return &PinnedCheckpointLaunchPlan{plan: planSpec}, nil
	}
	processor.recoveryEpoch = "direct-g1-epoch"
	if err := processor.save(); err != nil {
		t.Fatal(err)
	}
	processor = newCommandProcessor(cfg, ownedStopFixtureLogger(), true)
	processor.ownedStopPaths, processor.ownedStopPlanPath = paths, planPath
	processor.openOwnedStopPlan = func(_ context.Context, requested string) (*PinnedCheckpointLaunchPlan, error) {
		if requested != planPath {
			return nil, errors.New("direct G1 fixed plan selector drift")
		}
		return &PinnedCheckpointLaunchPlan{plan: planSpec}, nil
	}
	if processor.initError != nil || processor.recoveryEpoch != "direct-g1-epoch" {
		t.Fatalf("direct fixture baseline did not reload: epoch=%q error=%v", processor.recoveryEpoch, processor.initError)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	verifiedIPC := make(chan error, 2)
	ipcDone := make(chan struct{})
	go func() {
		defer close(ipcDone)
		for count := 0; count < 2; count++ {
			conn, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				verifiedIPC <- acceptErr
				return
			}
			deadlineErr := conn.SetDeadline(time.Now().Add(10 * time.Second))
			var request ownedStopRequest
			decodeErr := deadlineErr
			if decodeErr == nil {
				decodeErr = json.NewDecoder(io.LimitReader(conn, checkpointOwnedStopMaxFrame+1)).Decode(&request)
			}
			var reply ownedStopReply
			if decodeErr == nil {
				_, original, pending, verifyErr := verifyOwnedStopNodeIntentAt(ctx, request, sha256Hex(configBytes), paths)
				if verifyErr == nil && (pending.CommandID != original.ID || pending.SigningMaterialSHA256 != request.SigningSHA256 || !bytes.Equal(pending.PinnedRootStopPublicKey, public)) {
					verifyErr = errors.New("direct fixture pending intent differs from authenticated root request")
				}
				if verifyErr == nil {
					reply.Receipt, verifyErr = signOwnedStopFixtureReceipt(original, request, private)
				}
				decodeErr = verifyErr
			}
			if decodeErr != nil {
				reply.Error = "private fake root rejected direct same-process intent"
			}
			verifiedIPC <- decodeErr
			_ = json.NewEncoder(conn).Encode(reply)
			_ = conn.Close()
			if decodeErr != nil {
				return
			}
		}
	}()
	defer func() {
		_ = listener.Close()
		select {
		case <-ipcDone:
		case <-time.After(time.Second):
			t.Error("direct fixture IPC receiver did not stop after listener close")
		}
	}()
	command, err := ownedStopFixtureCommand(cfg.NodeID, strings.Repeat("a", 64), "victim.kv", sha256Hex(snapshot), processor.recoveryEpoch, secret)
	if err != nil {
		t.Fatal(err)
	}
	command.ID, command.IdempotencyKey = "direct-g1-victim", "direct-g1-victim-key"
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	victimResult := processor.Handle(ctx, command)
	if !victimResult.OK || victimResult.Uncertain {
		t.Fatalf("authentic fixture root receipt did not settle direct victim Handle: %+v", victimResult)
	}
	if err := <-verifiedIPC; err != nil {
		t.Fatalf("fake root did not verify the victim's durable write-ahead envelope: %v", err)
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	if processor.inflight[ownedStopFenceKey(accelerator)] || len(processor.pending) != 0 {
		t.Fatal("successful victim Handle did not clear its actual accelerator transition key")
	}
	urgent := command
	urgent.ID, urgent.IdempotencyKey = "direct-g1-urgent", "direct-g1-urgent-key"
	urgent.Args = make(map[string]any, len(command.Args))
	for key, value := range command.Args {
		urgent.Args[key] = value
	}
	urgent.Args["step_id"], urgent.Args["model"] = "urgent_stop", "owned-stop/urgent-model"
	urgent.Signature, err = wsproto.SignCommand(urgent, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	urgentResult := processor.Handle(ctx, urgent)
	if !urgentResult.OK || urgentResult.Uncertain {
		t.Fatalf("linked urgent Handle did not follow the directly acknowledged victim in the same processor: %+v", urgentResult)
	}
	if err := <-verifiedIPC; err != nil {
		t.Fatalf("fake root did not verify the urgent step's durable write-ahead envelope: %v", err)
	}
	operation := processor.ownedStopOperations[accelerator]
	if processor.inflight[ownedStopFenceKey(accelerator)] || len(processor.pending) != 0 || operation.Steps["victim_stop"].Status != "acknowledged" || operation.Steps["urgent_stop"].Status != "acknowledged" {
		t.Fatal("direct linked victim-to-urgent Handle did not durably settle both steps without retaining the accelerator in-flight key")
	}
	fmt.Println("__OWNED_STOP_G1_DIRECT_VICTIM_URGENT__")
}

func signOwnedStopFixtureReceipt(command wsproto.CommandPayload, request ownedStopRequest, private ed25519.PrivateKey) ([]byte, error) {
	binding := strings.TrimPrefix(fmt.Sprint(command.Args["local_checkpoint_binding"]), "sha256:")
	signedAt := time.Now().UTC()
	receipt := ownedStopReceipt{Version: 1, NodeID: command.NodeID, OperationID: fmt.Sprint(command.Args["operation_id"]), StepID: fmt.Sprint(command.Args["step_id"]), CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, OriginalEnvelopeSHA256: sha256Hex(request.Command), SigningMaterialSHA256: request.SigningSHA256, RecoveryEpoch: request.RecoveryEpoch, AcceleratorID: fmt.Sprint(command.Args["accelerator_id"]), FencingToken: int64FromArg(command.Args["fencing_token"]), TargetID: fmt.Sprint(command.Args["target_id"]), WorkloadID: fmt.Sprint(command.Args["workload_id"]), WorkloadRevision: int64FromArg(command.Args["workload_revision"]), Model: fmt.Sprint(command.Args["model"]), ModelAlias: fmt.Sprint(command.Args["model_alias"]), LocalCheckpointBinding: binding, ManagedCurrentIncarnation: binding, ManagedPlanSHA256: strings.Repeat("b", 64), CustodyBindingSHA256: strings.Repeat("c", 64), SnapshotName: fmt.Sprint(command.Args["snapshot_name"]), SnapshotDigest: fmt.Sprint(command.Args["snapshot_digest"]), SupervisorPID: 2, SupervisorStartTicks: 1, WorkerPID: 3, WorkerStartTicks: 1, InvocationID: strings.Repeat("a", 32), ControlGroup: "/system.slice/llama-server.service", SignalSent: true, ReleaseTerminal: true, SignedAt: signedAt.Format(time.RFC3339Nano)}
	unsigned, err := json.Marshal(receipt)
	if err != nil {
		return nil, err
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsigned)))
	return json.Marshal(receipt)
}

func ownedStopFixtureQuery(original wsproto.CommandPayload, secret string) wsproto.CommandPayload {
	args := make(map[string]any, len(original.Args)+5)
	for key, value := range original.Args {
		args[key] = value
	}
	wire, _ := wsproto.CanonicalCommandEnvelope(original)
	args["original_command_id"], args["original_idempotency_key"] = original.ID, original.IdempotencyKey
	args["original_envelope_sha256"] = sha256Hex(wire)
	args["expected_fence"], args["observed_after_fence"] = original.Args["fencing_token"], original.Args["fencing_token"]
	query := wsproto.CommandPayload{ID: "owned-stop-reconcile", IdempotencyKey: "owned-stop-reconcile-key", NodeID: original.NodeID, Command: "llm_displacement_stop_query", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(2 * time.Minute), Args: args}
	query.Signature, _ = wsproto.SignCommand(query, []byte(secret))
	return query
}

func ownedStopFixtureRequest(command wsproto.CommandPayload, public ed25519.PublicKey, secret string) (ownedStopRequest, error) {
	wire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		return ownedStopRequest{}, err
	}
	material, err := wsproto.CommandSigningMaterialForOwnedStop(command)
	if err != nil {
		return ownedStopRequest{}, err
	}
	if !wsproto.VerifyCommand(command, []byte(secret)) {
		return ownedStopRequest{}, errors.New("fixture stop command does not authenticate")
	}
	return ownedStopRequest{Command: wire, SigningSHA256: sha256Hex(material), RecoveryEpoch: fmt.Sprint(command.Args["recovery_epoch"]), PinnedPublicKey: append([]byte(nil), public...)}, nil
}

func rejectOwnedStopMalformedFrame(ctx context.Context, socket string) error {
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	if _, err := io.WriteString(conn, `{"unexpected":true}`+"\n"); err != nil {
		return err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("owned-stop malformed-frame fixture did not use a Unix socket")
	}
	if err := unixConn.CloseWrite(); err != nil {
		return err
	}
	var reply ownedStopReply
	if err := json.NewDecoder(conn).Decode(&reply); err != nil {
		return err
	}
	if reply.Error != "invalid request frame" || len(reply.Receipt) != 0 {
		return errors.New("root receiver did not reject the malformed request frame exactly")
	}
	return nil
}

type ownedStopKeyInfoFixture struct {
	mode os.FileMode
	size int64
	stat syscall.Stat_t
}

func (i ownedStopKeyInfoFixture) Name() string       { return "key" }
func (i ownedStopKeyInfoFixture) Size() int64        { return i.size }
func (i ownedStopKeyInfoFixture) Mode() os.FileMode  { return i.mode }
func (i ownedStopKeyInfoFixture) ModTime() time.Time { return time.Time{} }
func (i ownedStopKeyInfoFixture) IsDir() bool        { return false }
func (i ownedStopKeyInfoFixture) Sys() any           { return &i.stat }

func TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup(t *testing.T) {
	valid := ownedStopKeyInfoFixture{mode: 0o640, size: 64, stat: syscall.Stat_t{Uid: 0, Gid: 123, Nlink: 1}}
	if err := validateCheckpointOwnedStopKeyMetadata(valid, true, 123); err != nil {
		t.Fatalf("root-owned group-readable public key rejected: %v", err)
	}
	mutants := map[string]ownedStopKeyInfoFixture{
		"node-owned public key": func() ownedStopKeyInfoFixture { x := valid; x.stat.Uid = 1000; return x }(),
		"wrong public group":    func() ownedStopKeyInfoFixture { x := valid; x.stat.Gid = 124; return x }(),
		"writable public key":   func() ownedStopKeyInfoFixture { x := valid; x.mode = 0o660; return x }(),
		"linked public key":     func() ownedStopKeyInfoFixture { x := valid; x.stat.Nlink = 2; return x }(),
		"truncated public key":  func() ownedStopKeyInfoFixture { x := valid; x.size = 63; return x }(),
	}
	for name, mutant := range mutants {
		t.Run(name, func(t *testing.T) {
			if err := validateCheckpointOwnedStopKeyMetadata(mutant, true, 123); err == nil {
				t.Fatal("invalid public-key authority metadata was accepted")
			}
		})
	}
}

func TestOwnedStopSupervisorSuccessRequiresDurableAcknowledgement(t *testing.T) {
	if !ownedStopWaitResultAfterDurableAck(nil, nil) {
		t.Fatal("clean child exit after durable acknowledgement was rejected")
	}
	if ownedStopWaitResultAfterDurableAck(nil, errors.New("acknowledgement missing")) {
		t.Fatal("child exit without durable acknowledgement was normalized to success")
	}
	if ownedStopWaitResultAfterDurableAck(errors.New("unknown wait outcome"), nil) {
		t.Fatal("unknown child wait outcome was normalized to success")
	}
}

func TestCheckpointFixedOwnedStopRemoteKernelFixture(t *testing.T) {
	fixtureRoot := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	modelPath := os.Getenv("CHECKPOINT_CUSTODY_VERITY_FILE")
	if fixtureRoot == "" && modelPath == "" {
		return
	}
	if fixtureRoot == "" || modelPath == "" {
		t.Fatal("owned-stop kernel fixture requires the reviewed private fs-verity image")
	}
	fixtureRoot, err := filepath.Abs(fixtureRoot)
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(fixtureRoot, "owned-stop-")
	if err != nil {
		t.Fatal(err)
	}
	baseInfo, err := os.Lstat(base)
	if err != nil || !baseInfo.IsDir() || baseInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatal("owned-stop fixture directory could not be pinned")
	}
	fixtureCleanupComplete := false
	defer func() {
		current, err := os.Lstat(base)
		if err != nil || !os.SameFile(baseInfo, current) || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || filepath.Dir(base) != fixtureRoot || !strings.HasPrefix(filepath.Base(base), "owned-stop-") {
			t.Errorf("owned-stop fixture directory identity changed; preserving fixture: %v", err)
			return
		}
		if !fixtureCleanupComplete {
			t.Errorf("owned-stop fixture custody did not reach exact terminal cleanup; preserving %s", base)
			return
		}
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove exact owned-stop fixture directory: %v", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	paths, cfg, planPath, spec, snapshotName, snapshotDigest, secret, public, private, err := makeOwnedStopKernelFixture(base, modelPath)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := openOwnedStopFixturePlan(planPath, base, baseInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Close()
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: spec.Custody.Root, MaxArtifactBytes: spec.Custody.MaxArtifactBytes, MaxStagingBytes: spec.Custody.MaxStagingBytes, ReserveBytes: spec.Custody.ReserveBytes})
	if err != nil {
		t.Fatal(err)
	}
	modelSum, modelSize, err := fileDigest(modelPath)
	if err != nil || modelSize != spec.Model.Bytes || modelSum != spec.Model.SHA256 {
		t.Fatal("approved fs-verity model source changed before controlled preparation")
	}
	prepared, err := store.Prepare(ctx, CheckpointCustodySource{Path: modelPath, ApprovedSHA256: spec.Model.SHA256, ExpectedBytes: spec.Model.Bytes})
	if err != nil {
		t.Fatal(err)
	}
	preparedTransferred := false
	defer func() {
		if preparedTransferred {
			return
		}
		if err := prepared.Discard(ctx); err != nil {
			t.Errorf("discard pre-launch prepared custody: %v; preserving fixture", err)
			return
		}
		fixtureCleanupComplete = true
	}()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command, _, err := fixedCheckpointPlacementCommand(executable, spec, CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: spec.Placement.PhysicalIdentity, ChildMaskUUID: spec.Placement.PhysicalIdentity, RuntimeDeviceToken: spec.Placement.RuntimeDeviceToken, RuntimeVersion: spec.Placement.RuntimeVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)})
	if err != nil {
		t.Fatal(err)
	}
	command.Env = []string{ownedStopCPUWorkerEnv + "=1", "CHECKPOINT_CUSTODY_ENDPOINT=" + net.JoinHostPort(spec.Endpoint.Host, strconv.Itoa(spec.Endpoint.Port)), "CHECKPOINT_CUSTODY_ALIAS=" + spec.Alias}
	launch, err := store.beginFixedContext(ctx, prepared, CheckpointCustodyLaunchRequest{Command: command, Endpoint: managedCheckpointEndpoint(spec), ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: spec.Alias, ExpectedExecutableSHA256: spec.Executable.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	preparedTransferred = true
	var waitDone chan struct{}
	var waitResult error
	var receiver *checkpointOwnedStopServer
	launchStarted := false
	registerWaiter := func() {
		if waitDone != nil {
			return
		}
		waitDone = make(chan struct{})
		go func() {
			waitResult = launch.WaitContext(ctx)
			close(waitDone)
		}()
	}
	defer func() {
		if receiver != nil {
			if err := receiver.Close(); err != nil {
				t.Errorf("close exact owned-stop receiver: %v", err)
			}
		}
		if !launchStarted {
			if err := launch.Abort(); err != nil {
				t.Errorf("abort pre-start owned launch: %v; preserving fixture", err)
				return
			}
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			err := launch.ReleaseTerminal(cleanup)
			stop()
			if err != nil {
				t.Errorf("release pre-start terminal custody: %v; preserving fixture", err)
				return
			}
			fixtureCleanupComplete = true
			return
		}
		if launchStarted {
			// Commit owns the pre-commit liveness check and rejects registration
			// of the single WaitContext owner before it completes. On every
			// post-Start failure path, register exactly one waiter here before
			// signaling or releasing custody.
			registerWaiter()
			select {
			case <-waitDone:
			default:
				launch.mu.Lock()
				pidfd := launch.pidfd
				var signalErr error
				if pidfd >= 0 {
					signalErr = unix.PidfdSendSignal(pidfd, syscall.SIGTERM, nil, 0)
				}
				launch.mu.Unlock()
				if signalErr != nil && !errors.Is(signalErr, unix.ESRCH) {
					t.Errorf("signal exact owned child during cleanup: %v; preserving fixture", signalErr)
					return
				}
				select {
				case <-waitDone:
				case <-time.After(3 * time.Second):
					t.Errorf("exact owned child did not reap during cleanup; preserving fixture")
					return
				}
			}
			select {
			case <-waitDone:
			default:
				t.Errorf("single waiter has no positive exact reap; preserving fixture")
				return
			}
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			releaseErr := launch.ReleaseTerminal(cleanup)
			stop()
			launch.mu.Lock()
			cleanupComplete := launch.reaped && launch.terminal && launch.released
			launch.mu.Unlock()
			if releaseErr != nil || !cleanupComplete {
				t.Errorf("exact owned custody terminal release unconfirmed (%v); preserving fixture", releaseErr)
				return
			}
			fixtureCleanupComplete = true
		}
	}()
	if err := launch.Start(); err != nil {
		t.Fatal(err)
	}
	launchStarted = true
	unrelated := exec.Command("/usr/bin/sleep", "120")
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unrelated.Process != nil {
			_ = unrelated.Process.Kill()
			_ = unrelated.Wait()
		}
	}()
	unrelatedPID := unrelated.Process.Pid
	unrelatedTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unrelatedPID)), unrelatedPID)
	if err != nil || unrelatedTicks == 0 {
		t.Fatal("independent local CPU control process is not identifiable")
	}
	if err := waitFixedListener(ctx, spec.Endpoint.Host, spec.Endpoint.Port); err != nil {
		t.Fatal(err)
	}
	if err := launch.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	registerWaiter()
	verification, ok, err := store.VerifyBinding(ctx, managedCheckpointEndpoint(spec), checkpointIdentityServiceUnit)
	if err != nil || !ok || verification.EvidenceKind != "controlled-source-fs-verity-v2" || verification.ModelArgument != "/proc/self/fd/4" {
		t.Fatalf("actual controlled fs-verity receipt was not verified: ok=%t err=%v", ok, err)
	}
	workerPID := launch.cmd.Process.Pid
	invocation := strings.Repeat("a", 32)
	workerCgroup, err := ownedStopProcessCgroup(ctx, workerPID)
	if err != nil {
		t.Fatal(err)
	}
	unitObserver := func(callCtx context.Context) (checkpointFixedUnitState, error) {
		if err := callCtx.Err(); err != nil {
			return checkpointFixedUnitState{}, err
		}
		return checkpointFixedUnitState{MainPID: workerPID, Invocation: invocation, ControlGroup: workerCgroup, Active: "active", Sub: "running"}, nil
	}
	bindingObserver := func(callCtx context.Context) (CheckpointManagedBinding, error) {
		return observeOwnedStopKernelManagedBinding(callCtx, planPath, base, baseInfo, spec, store, verification, workerPID, invocation, workerCgroup)
	}
	binding, err := bindingObserver(ctx)
	if err != nil {
		t.Fatalf("fresh source/executable/argv/listener/alias managed binding failed: %v", err)
	}
	_, publicAgain, err := ensureCheckpointOwnedStopKeysAt(paths)
	if err != nil || !bytes.Equal(publicAgain, public) {
		t.Fatal("root acknowledgement key pin changed during private fixture setup")
	}
	if err := os.Chmod(filepath.Dir(paths.Socket), 0o750); err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.Socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(paths.Socket, 0o660); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(true)
	paths.NodeUID, paths.NodeGID, paths.principalPinned = 0, 0, true
	paths.syncReceiptDir = func(string) error {
		return nil
	}
	var directorySyncs atomic.Int32
	paths.syncReceiptDir = func(string) error {
		if directorySyncs.Add(1) == 1 {
			return errors.New("fixture receipt parent fsync fault after rename")
		}
		return nil
	}
	processor, err := ownedStopFixtureProcessor(cfg, paths, planPath, baseInfo)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	processor.recoveryEpoch = "owned-stop-fixture-epoch"
	if err := processor.save(); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	processor, err = ownedStopFixtureProcessor(cfg, paths, planPath, baseInfo)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	processor.openOwnedStopPlan = func(_ context.Context, path string) (*PinnedCheckpointLaunchPlan, error) {
		if path != planPath {
			return nil, errors.New("fixture plan path drift")
		}
		return openOwnedStopFixturePlan(planPath, base, baseInfo)
	}
	commandPayload, err := ownedStopFixtureCommand(cfg.NodeID, binding.CurrentIncarnation, snapshotName, snapshotDigest, processor.recoveryEpoch, secret)
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	intentReady := make(chan struct{})
	allowIntent := make(chan struct{})
	var intentReleased atomic.Bool
	releaseIntent := func() {
		if intentReleased.CompareAndSwap(false, true) {
			close(allowIntent)
		}
	}
	defer releaseIntent()
	var intentBarrierClaimed atomic.Bool
	receiverDiagnostics := make(chan string, 4)
	server := &checkpointOwnedStopServer{listener: listener, private: private, public: public, secret: secret, configSHA256: sha256Hex(mustReadFile(t, paths.NodeConfig)), config: cfg, plan: plan, launch: launch, waitDone: waitDone, waitErr: &waitResult, ackDone: make(chan struct{}), connections: make(chan struct{}, 4), paths: paths, waiterReady: true, unitObserver: unitObserver, bindingObserver: bindingObserver, testDiagnostic: func(stage, cause string) {
		select {
		case receiverDiagnostics <- stage + ": " + cause:
		default:
		}
	}, afterIntent: func() {
		if intentBarrierClaimed.CompareAndSwap(false, true) {
			close(intentReady)
			select {
			case <-allowIntent:
			case <-ctx.Done():
			}
		}
	}}
	receiver = server
	go server.serve()
	if err := rejectOwnedStopMalformedFrame(ctx, paths.Socket); err != nil {
		t.Fatal(err)
	}
	future := commandPayload
	future.ID, future.IdempotencyKey = "owned-stop-future", "owned-stop-future-key"
	future.IssuedAt = time.Now().UTC().Add(30 * time.Second)
	future.ExpiresAt = future.IssuedAt.Add(time.Minute)
	future.Signature, err = wsproto.SignCommand(future, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	futureResult := processor.Handle(ctx, future)
	if futureResult.OK || futureResult.Uncertain {
		t.Fatalf("future-issued stop reached an external-effect or uncertain boundary: %+v", futureResult)
	}
	if _, exists := processor.pending[future.ID]; exists || server.ackIsDone() {
		t.Fatal("future-issued stop changed durable intent or supervisor lifetime")
	}
	select {
	case <-waitDone:
		t.Fatal("future-issued stop signaled/reaped the owned worker")
	default:
	}
	validRequest, err := ownedStopFixtureRequest(commandPayload, public, secret)
	if err != nil {
		t.Fatal(err)
	}
	forgedCommand := commandPayload
	forgedCommand.Signature = strings.Repeat("0", len(forgedCommand.Signature))
	forgedWire, err := wsproto.CanonicalCommandEnvelope(forgedCommand)
	if err != nil {
		t.Fatal(err)
	}
	forgedRequest := validRequest
	forgedRequest.Command = forgedWire
	firstResultCh := make(chan wsproto.CommandResultPayload, 1)
	go func() { firstResultCh <- processor.Handle(ctx, commandPayload) }()
	select {
	case <-intentReady:
	case earlyResult := <-firstResultCh:
		select {
		case diagnostic := <-receiverDiagnostics:
			t.Fatalf("valid signed Handle returned before receiver intent barrier: id=%q ok=%t uncertain=%t error=%q receiver=%q", earlyResult.ID, earlyResult.OK, earlyResult.Uncertain, earlyResult.Error, diagnostic)
		default:
			t.Fatalf("valid signed Handle returned before receiver intent barrier without receiver diagnostic: id=%q ok=%t uncertain=%t error=%q", earlyResult.ID, earlyResult.OK, earlyResult.Uncertain, earlyResult.Error)
		}
	case <-ctx.Done():
		select {
		case earlyResult := <-firstResultCh:
			select {
			case diagnostic := <-receiverDiagnostics:
				t.Fatalf("valid signed Handle returned before receiver intent barrier as context ended: id=%q ok=%t uncertain=%t error=%q receiver=%q", earlyResult.ID, earlyResult.OK, earlyResult.Uncertain, earlyResult.Error, diagnostic)
			default:
				t.Fatalf("valid signed Handle returned before receiver intent barrier as context ended without receiver diagnostic: id=%q ok=%t uncertain=%t error=%q", earlyResult.ID, earlyResult.OK, earlyResult.Uncertain, earlyResult.Error)
			}
		case <-time.After(time.Second):
			t.Fatalf("valid signed Handle did not reach the receiver after persisting its intent or return a result within the bounded diagnostic interval: context=%v", ctx.Err())
		}
	}
	intentReload, err := ownedStopFixtureProcessor(cfg, paths, planPath, baseInfo)
	if err != nil {
		t.Fatal(err)
	}
	if _, durablePending := intentReload.pending[commandPayload.ID]; !durablePending {
		t.Fatal("forged-envelope control did not follow a real fsynced pending intent")
	}
	if _, err := invokeOwnedStopSupervisorAt(ctx, forgedRequest, paths.Socket); err == nil {
		t.Fatal("root receiver accepted an HMAC-invalid original envelope")
	}
	launch.mu.Lock()
	untouched := !launch.reaped && !launch.terminal && !launch.released
	launch.mu.Unlock()
	if !untouched || server.ackIsDone() {
		t.Fatal("forged envelope caused signal/reap/terminal release/root acknowledgement")
	}
	if _, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(workerPID)), workerPID); err != nil {
		t.Fatalf("forged envelope stopped the still-owned worker: %v", err)
	}
	select {
	case <-waitDone:
		t.Fatal("forged envelope reaped the still-owned worker")
	default:
	}
	wrongKeyRequest := validRequest
	wrongKeyRequest.PinnedPublicKey = append([]byte(nil), validRequest.PinnedPublicKey...)
	wrongKeyRequest.PinnedPublicKey[0] ^= 1
	if _, err := invokeOwnedStopSupervisorAt(ctx, wrongKeyRequest, paths.Socket); err == nil {
		t.Fatal("root receiver accepted a changed pinned acknowledgement key")
	}
	if server.ackIsDone() {
		t.Fatal("invalid original envelope or changed key acknowledged the worker stop")
	}
	select {
	case <-waitDone:
		t.Fatal("invalid original envelope or changed key signaled/reaped the owned worker")
	default:
	}
	releaseIntent()
	firstResult := <-firstResultCh
	if firstResult.OK || !firstResult.Uncertain {
		t.Fatalf("receipt directory sync failure was not returned as an uncertain stop: %+v", firstResult)
	}
	pending, ok := processor.pending[commandPayload.ID]
	if !ok || pending.Command != "llm_displacement_stop" || server.ackIsDone() {
		t.Fatal("rename-before-directory-sync uncertainty removed pending custody or acknowledged early")
	}
	restarted, err := ownedStopFixtureProcessor(cfg, paths, planPath, baseInfo)
	if err != nil {
		t.Fatal(err)
	}
	restarted.openOwnedStopPlan = processor.openOwnedStopPlan
	var loseReply atomic.Bool
	loseReply.Store(true)
	server.dropReply = func() bool { return loseReply.CompareAndSwap(true, false) }
	request := ownedStopRequest{Command: append([]byte(nil), pending.OriginalEnvelope...), SigningSHA256: pending.SigningMaterialSHA256, RecoveryEpoch: pending.StopRecoveryEpoch, PinnedPublicKey: append([]byte(nil), pending.PinnedRootStopPublicKey...)}
	if _, err := invokeOwnedStopSupervisorAt(ctx, request, paths.Socket); err == nil {
		t.Fatal("fixture did not lose the exact retry reply")
	}
	if !server.ackIsDone() {
		t.Fatal("exact durable receipt retry did not release the single supervisor acknowledgement wait")
	}
	<-waitDone
	if !ownedStopExpectedWaitResult(waitResult) {
		t.Fatalf("single owned waiter did not confirm the signaled worker reap: %v", waitResult)
	}
	launch.mu.Lock()
	terminalRelease := launch.reaped && launch.terminal && launch.released
	launch.mu.Unlock()
	if !terminalRelease {
		t.Fatal("actual controlled source was not reaped and ReleaseTerminal before root acknowledgement")
	}
	if currentTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(unrelatedPID)), unrelatedPID); err != nil || currentTicks != unrelatedTicks {
		t.Fatalf("owned-stop signal affected an unrelated child: start_ticks=%d current=%d err=%v", unrelatedTicks, currentTicks, err)
	}
	query := ownedStopFixtureQuery(commandPayload, secret)
	var rotateDuringQuery atomic.Bool
	rotateDuringQuery.Store(true)
	rotationSync := func(string) error {
		if rotateDuringQuery.CompareAndSwap(true, false) {
			rotated := append([]byte(nil), public...)
			rotated[0] ^= 1
			return os.WriteFile(paths.PublicKey, []byte(hex.EncodeToString(rotated)), 0o640)
		}
		return nil
	}
	paths.syncReceiptDir, restarted.ownedStopPaths.syncReceiptDir, server.paths.syncReceiptDir = rotationSync, rotationSync, rotationSync
	queryResult := restarted.Handle(ctx, query)
	if queryResult.OK || len(restarted.pending) == 0 {
		t.Fatalf("receipt query accepted a root-key rotation during held receipt verification: %+v", queryResult)
	}
	if err := os.WriteFile(paths.PublicKey, []byte(hex.EncodeToString(public)), 0o640); err != nil {
		t.Fatal(err)
	}
	paths.syncReceiptDir, restarted.ownedStopPaths.syncReceiptDir, server.paths.syncReceiptDir = func(string) error { return nil }, func(string) error { return nil }, func(string) error { return nil }
	query.ID, query.IdempotencyKey = "owned-stop-reconcile-restored", "owned-stop-reconcile-restored-key"
	query.Signature, err = wsproto.SignCommand(query, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	queryResult = restarted.Handle(ctx, query)
	if !queryResult.OK || queryResult.Result["receipt_sha256"] == "" {
		t.Fatalf("direct exact signed receipt query failed to reconcile restart: %+v", queryResult)
	}
	completed, err := ownedStopFixtureProcessor(cfg, paths, planPath, baseInfo)
	if err != nil {
		t.Fatal(err)
	}
	completed.openOwnedStopPlan = processor.openOwnedStopPlan
	if len(completed.pending) != 0 || !completed.ownedStopQueryMatchesPending(query) {
		t.Fatal("restart did not durably reconcile the original operation before a linked next step")
	}
	urgent := commandPayload
	urgent.ID, urgent.IdempotencyKey = "owned-stop-urgent", "owned-stop-urgent-key"
	urgent.Args = make(map[string]any, len(commandPayload.Args))
	for key, value := range commandPayload.Args {
		urgent.Args[key] = value
	}
	urgent.Args["step_id"] = "urgent_stop"
	urgent.Signature, err = wsproto.SignCommand(urgent, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	intent, hasIntent, err := completed.commandIntentWithPlanSpec(urgent, spec)
	if err != nil || !hasIntent || completed.checkOwnedStopTransition(urgent) != nil || intent.Token != int64FromArg(urgent.Args["fencing_token"]) {
		t.Fatalf("same-operation same-accelerator urgent step did not follow verified recovery: intent=%+v err=%v", intent, err)
	}
	unrelatedStop := urgent
	unrelatedStop.ID, unrelatedStop.IdempotencyKey = "unrelated-stop", "unrelated-stop-key"
	unrelatedStop.Args = make(map[string]any, len(urgent.Args))
	for key, value := range urgent.Args {
		unrelatedStop.Args[key] = value
	}
	unrelatedStop.Args["operation_id"], unrelatedStop.Args["step_id"] = "unrelated-op", "victim_stop"
	if completed.checkOwnedStopTransition(unrelatedStop) == nil {
		t.Fatal("unrelated operation reused the accelerator fence after a linked receipt")
	}
	fmt.Println("__OWNED_STOP_G2_FIXTURE_POSITIVE__")
}

func TestCheckpointFixedLauncherLinuxParsersFailClosed(t *testing.T) {
	good := []byte("MainPID=234\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/llama-server.service\nActiveState=activating\nSubState=start\n")
	if got, err := parseCheckpointFixedUnit(good); err != nil || got.MainPID != 234 || got.Active != "activating" {
		t.Fatalf("valid private activating state rejected: %#v, %v", got, err)
	}
	bad := [][]byte{
		[]byte("MainPID=234\nMainPID=235\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/llama-server.service\nActiveState=activating\nSubState=start\n"),
		[]byte("MainPID=234\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/llama-server.service\nActiveState=active\nSubState=running\n"),
		[]byte("MainPID=234\nInvocationID=00000000000000000000000000000000\nControlGroup=/system.slice/llama-server.service\nActiveState=activating\nSubState=start\n"),
		[]byte("MainPID=234\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/../llama-server.service\nActiveState=activating\nSubState=start\n"),
	}
	for i, input := range bad {
		if _, err := parseCheckpointFixedUnit(input); err == nil {
			t.Fatalf("malformed/private-state fault %d accepted", i)
		}
	}
	public, err := parseCheckpointUnitProperties(good)
	if err != nil {
		t.Fatalf("strict public observer parser rejected well-formed startup properties: %v", err)
	}
	binding, identity, first, second := checkpointUnitJoinFixture()
	first.ActiveState, second.ActiveState = public.ActiveState, public.ActiveState
	first.SubState, second.SubState = public.SubState, public.SubState
	if _, err := joinCheckpointUnitIdentity(binding, identity, "model-alias", first, second); err == nil {
		t.Fatal("public unit identity join accepted activating startup state")
	}
}

func TestCheckpointFixedLauncherLinuxNotifyBarrierSCMRights(t *testing.T) {
	listener, notify := newCheckpointFixedNotifyFixture(t)
	result := make(chan error, 1)
	go func() {
		_, oob := make([]byte, 256), make([]byte, unix.CmsgSpace(4))
		buf := make([]byte, 256)
		n, oobn, _, _, err := listener.ReadMsgUnix(buf, oob)
		if err != nil {
			result <- err
			return
		}
		if string(buf[:n]) != "BARRIER=1" {
			result <- errors.New("unexpected barrier datagram")
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			result <- err
			return
		}
		if len(messages) != 1 {
			result <- errors.New("barrier did not carry exactly one ancillary message")
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil {
			result <- err
			return
		}
		if len(fds) != 1 {
			result <- errors.New("barrier did not carry exactly one descriptor")
			return
		}
		defer unix.Close(fds[0])
		result <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := notify.Barrier(ctx); err != nil {
		t.Fatalf("real Unix SCM_RIGHTS barrier failed: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointFixedLauncherLinuxNotifyBarrierRejectsUnexpectedData(t *testing.T) {
	listener, notify := newCheckpointFixedNotifyFixture(t)
	result := make(chan error, 1)
	go func() {
		buf := make([]byte, 256)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, err := listener.ReadMsgUnix(buf, oob)
		if err != nil {
			result <- err
			return
		}
		if string(buf[:n]) != "BARRIER=1" {
			result <- errors.New("unexpected barrier datagram")
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil {
			result <- err
			return
		}
		if len(messages) != 1 {
			result <- errors.New("barrier ancillary count mismatch")
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			result <- errors.New("barrier descriptor count mismatch")
			return
		}
		_, err = unix.Write(fds[0], []byte("x"))
		_ = unix.Close(fds[0])
		result <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := notify.Barrier(ctx)
	if err == nil || !strings.Contains(err.Error(), "unexpected data") {
		t.Fatalf("barrier accepted bytes instead of closure: %v", err)
	}
	if fixtureErr := <-result; fixtureErr != nil {
		t.Fatal(fixtureErr)
	}
}

func TestCheckpointFixedLauncherLinuxNotifyBarrierHonorsCancellation(t *testing.T) {
	listener, notify := newCheckpointFixedNotifyFixture(t)
	result := make(chan int, 1)
	go func() {
		buf := make([]byte, 256)
		oob := make([]byte, unix.CmsgSpace(4))
		_, oobn, _, _, err := listener.ReadMsgUnix(buf, oob)
		if err != nil {
			result <- -1
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(messages) != 1 {
			result <- -1
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			result <- -1
			return
		}
		result <- fds[0]
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	err := notify.Barrier(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("barrier did not honor its context bound: %v", err)
	}
	fd := <-result
	if fd < 0 {
		t.Fatal("fixture did not receive the barrier descriptor")
	}
	_ = unix.Close(fd)
}

func TestCheckpointFixedLauncherLinuxNotifySendHonorsFullQueueAndRecovers(t *testing.T) {
	listener, notify := newCheckpointFixedNotifyFixture(t)
	fillers := fillNotifyQueue(t, notify.socket)
	_ = fillers
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := notify.Ready(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("full notification queue did not honor context bound: %v", err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf, oob := make([]byte, 256), make([]byte, unix.CmsgSpace(4))
	drained := 0
	for {
		if _, _, _, _, err := listener.ReadMsgUnix(buf, oob); err != nil {
			if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
				t.Fatalf("draining full notification queue failed: %v", err)
			}
			break
		}
		drained++
	}
	if drained == 0 {
		t.Fatal("fixture failed to saturate notification receive queue")
	}
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		buf, oob := make([]byte, 256), make([]byte, unix.CmsgSpace(4))
		n, oobn, _, _, err := listener.ReadMsgUnix(buf, oob)
		if err != nil {
			result <- err
			return
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || string(buf[:n]) != "BARRIER=1" || len(messages) != 1 {
			result <- errors.New("recovery barrier message or ancillary data was malformed")
			return
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			result <- errors.New("recovery barrier did not carry exactly one descriptor")
			return
		}
		result <- unix.Close(fds[0])
	}()
	if err := notify.Barrier(context.Background()); err != nil {
		t.Fatalf("notification did not recover after queue drain: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func fillNotifyQueue(t *testing.T, path string) []int {
	t.Helper()
	message := make([]byte, 512)
	fillers := make([]int, 0, 32)
	t.Cleanup(func() {
		for _, fd := range fillers {
			_ = unix.Close(fd)
		}
	})
	for client := 0; client < 32; client++ {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		fillers = append(fillers, fd)
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 64<<10); err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(fd, &unix.SockaddrUnix{Name: path}); err != nil {
			t.Fatal(err)
		}
		for sent := 0; sent < 128; sent++ {
			if _, err := unix.SendmsgN(fd, message, nil, nil, 0); err == nil {
				continue
			} else if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				break
			} else if err != unix.EINTR {
				t.Fatalf("filling notification queue failed: %v", err)
			}
		}
		probe, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Connect(probe, &unix.SockaddrUnix{Name: path}); err != nil {
			_ = unix.Close(probe)
			t.Fatal(err)
		}
		_, probeErr := unix.SendmsgN(probe, message, nil, nil, 0)
		_ = unix.Close(probe)
		if probeErr == unix.EAGAIN || probeErr == unix.EWOULDBLOCK {
			return fillers
		}
		if probeErr != nil && probeErr != unix.EINTR {
			t.Fatal(probeErr)
		}
		if client == 31 {
			t.Fatal("fixture could not block an independent Unix datagram sender")
		}
	}
	t.Fatal("fixture could not block an independent Unix datagram sender")
	return nil
}

func newCheckpointFixedNotifyFixture(t *testing.T) (*net.UnixConn, *checkpointFixedLinuxNotify) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.sock")
	addr := &net.UnixAddr{Name: path, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 1)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil {
		t.Fatal(socketErr)
	}
	if err := listener.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(path) })
	return listener, &checkpointFixedLinuxNotify{socket: path}
}
