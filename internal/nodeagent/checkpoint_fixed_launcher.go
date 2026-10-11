package nodeagent

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	checkpointFixedPlanPath        = "/etc/vram-governor/llama-server-plan.json"
	checkpointFixedCustodyRoot     = "/var/lib/vram-governor/checkpoint-custody"
	checkpointFixedSnapshotRoot    = "/var/lib/vram-governor/checkpoint-snapshots"
	checkpointFixedNodeConfigPath  = "/etc/vram-governor/node-agent.yaml"
	checkpointFixedNodeStatePath   = "/var/lib/vram-governor/node-command-state.json"
	checkpointFixedStopSocketPath  = "/run/vram-governor-owned-stop/stop.sock"
	checkpointFixedStopPrivateDir  = "/var/lib/vram-governor-stop-private"
	checkpointFixedStopPublicDir   = "/var/lib/vram-governor-stop-public"
	checkpointFixedStopKeyPath     = checkpointFixedStopPrivateDir + "/ed25519.key"
	checkpointFixedStopPublicPath  = checkpointFixedStopPublicDir + "/ed25519.pub"
	checkpointFixedStopReceiptDir  = checkpointFixedStopPublicDir + "/receipts"
	checkpointFixedNotifyTimeout   = 5 * time.Second
	checkpointFixedStartupTimeout  = 45 * time.Second
	checkpointFixedListenerTimeout = 30 * time.Second
)

type checkpointFixedUnitState struct {
	MainPID      int
	Invocation   string
	ControlGroup string
	Active       string
	Sub          string
}

type ownedStopReceipt struct {
	Version                   int    `json:"version"`
	NodeID                    string `json:"node_id"`
	OperationID               string `json:"operation_id"`
	StepID                    string `json:"step_id"`
	CommandID                 string `json:"command_id"`
	IdempotencyKey            string `json:"idempotency_key"`
	OriginalEnvelopeSHA256    string `json:"original_envelope_sha256"`
	SigningMaterialSHA256     string `json:"signing_material_sha256"`
	RecoveryEpoch             string `json:"recovery_epoch"`
	AcceleratorID             string `json:"accelerator_id"`
	FencingToken              int64  `json:"fencing_token"`
	TargetID                  string `json:"target_id"`
	WorkloadID                string `json:"workload_id"`
	WorkloadRevision          int64  `json:"workload_revision"`
	Model                     string `json:"model"`
	ModelAlias                string `json:"model_alias"`
	LocalCheckpointBinding    string `json:"local_checkpoint_binding"`
	ManagedCurrentIncarnation string `json:"managed_current_incarnation"`
	ManagedPlanSHA256         string `json:"managed_plan_sha256"`
	CustodyBindingSHA256      string `json:"custody_binding_sha256"`
	SnapshotName              string `json:"snapshot_name"`
	SnapshotDigest            string `json:"snapshot_digest"`
	SupervisorPID             int    `json:"supervisor_pid"`
	SupervisorStartTicks      uint64 `json:"supervisor_start_ticks"`
	WorkerPID                 int    `json:"worker_pid"`
	WorkerStartTicks          uint64 `json:"worker_start_ticks"`
	InvocationID              string `json:"invocation_id"`
	ControlGroup              string `json:"control_group"`
	SignalSent                bool   `json:"signal_sent"`
	ReleaseTerminal           bool   `json:"release_terminal"`
	SignedAt                  string `json:"signed_at"`
	Signature                 string `json:"signature"`
}

type ownedStopRequest struct {
	Command         []byte `json:"command"`
	SigningSHA256   string `json:"signing_sha256"`
	RecoveryEpoch   string `json:"recovery_epoch"`
	PinnedPublicKey []byte `json:"pinned_public_key"`
}

type ownedStopReply struct {
	Receipt []byte `json:"receipt,omitempty"`
	Error   string `json:"error,omitempty"`
}

// checkpointOwnedStopPaths is built internally from fixed production paths.
// Linux tests may construct a private fixture value from their own test file;
// no public API accepts path overrides.
type checkpointOwnedStopPaths struct {
	NodeConfig      string
	NodeEnv         string
	NodeState       string
	Socket          string
	PrivateKey      string
	PublicKey       string
	ReceiptDir      string
	SnapshotRoot    string
	TrustedRoot     string
	ConfigRoot      string
	StateDir        string
	NodeUID         uint32
	NodeGID         uint32
	principalPinned bool
	syncReceiptDir  func(string) error
}

func fixedCheckpointOwnedStopPaths() checkpointOwnedStopPaths {
	return checkpointOwnedStopPaths{
		NodeConfig:   checkpointFixedNodeConfigPath,
		NodeEnv:      "/etc/vram-governor/node-agent.env",
		NodeState:    checkpointFixedNodeStatePath,
		Socket:       checkpointFixedStopSocketPath,
		PrivateKey:   checkpointFixedStopKeyPath,
		PublicKey:    checkpointFixedStopPublicPath,
		ReceiptDir:   checkpointFixedStopReceiptDir,
		SnapshotRoot: checkpointFixedSnapshotRoot,
		TrustedRoot:  "/var/lib",
		ConfigRoot:   "/etc/vram-governor",
		StateDir:     "/var/lib/vram-governor",
	}
}

// CheckpointFixedLauncherResult reports only startup association facts. It is
// not a checkpoint capability or a GPU residency claim.
// RunCheckpointFixedLauncher runs the locally pinned canonical plan installed
// at the one fixed path. It accepts no command, argv, or environment inputs.
// The root-controlled supervisor remains alive until its child is reaped.
func RunCheckpointFixedLauncher(ctx context.Context) error {
	if ctx == nil {
		return errors.New("fixed checkpoint launcher context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return runCheckpointFixedLauncherPlatform(ctx)
}

func validateCheckpointFixedPlan(plan CheckpointLaunchPlan) error {
	if plan.Custody.Root != checkpointFixedCustodyRoot || plan.SnapshotRoot != checkpointFixedSnapshotRoot {
		return errors.New("fixed plan custody or snapshot root is outside the service writable paths")
	}
	return nil
}

type checkpointFixedPlan interface {
	Spec() CheckpointLaunchPlan
	Arguments() []string
	Recheck(context.Context) error
	Close() error
}

type checkpointFixedNotify interface {
	MainPID(context.Context, int) error
	Barrier(context.Context) error
	Ready(context.Context) error
}

type checkpointFixedSupervisor struct {
	mu      sync.Mutex
	plan    checkpointFixedPlan
	model   *CheckpointPreparedModel
	launch  *CheckpointControlledLaunch
	notify  checkpointFixedNotify
	settled bool
}

type checkpointFixedStartupSample struct {
	unit                 checkpointFixedUnitState
	binding              CheckpointCustodyVerification
	identity             CheckpointLocalIdentity
	placement            CheckpointDevicePlacement
	footprint            checkpointOffloadEvidence
	childParent          int
	supervisorStartTicks uint64
	childCgroup          string
	supervisorCgroup     string
}

type checkpointFixedStartupSteps struct {
	commit  func(context.Context) error
	mainPID func(context.Context, int) error
	barrier func(context.Context) error
	join    func(context.Context) error
	ready   func(context.Context) error
}

func runCheckpointFixedStartupSteps(ctx context.Context, pid int, steps checkpointFixedStartupSteps) error {
	if ctx == nil || pid <= 1 || steps.commit == nil || steps.mainPID == nil || steps.barrier == nil || steps.join == nil || steps.ready == nil {
		return errors.New("fixed startup protocol steps are incomplete")
	}
	for _, step := range []func() error{
		func() error { return steps.commit(ctx) },
		func() error { return steps.mainPID(ctx, pid) },
		func() error { return steps.barrier(ctx) },
		func() error { return steps.join(ctx) },
		func() error { return steps.ready(ctx) },
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func runCheckpointFixedCommitAfterReadiness(ctx context.Context, wait func(context.Context) error, commit func(context.Context) error) error {
	if ctx == nil || wait == nil || commit == nil {
		return errors.New("fixed custody commit requires readiness and commit callbacks")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := wait(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return commit(ctx)
}

func cleanupCheckpointFixedOwnedChild(ctx context.Context, signalAndReap func(context.Context) (bool, error), release func(context.Context) error) error {
	if ctx == nil || signalAndReap == nil || release == nil {
		return errors.New("fixed owned-child cleanup steps are incomplete")
	}
	reaped, waitErr := signalAndReap(ctx)
	if !reaped {
		if waitErr != nil {
			return waitErr
		}
		return errors.New("fixed child reap could not be confirmed")
	}
	return errors.Join(waitErr, release(ctx))
}

type checkpointFixedRetentionSeam struct {
	state    func() (settled bool, pidfd int)
	signal   func(int) error
	release  func(context.Context) error
	interval time.Duration
}

func retainCheckpointFixedOwnership(ctx context.Context, seam checkpointFixedRetentionSeam) error {
	if ctx == nil || seam.state == nil || seam.signal == nil || seam.release == nil || seam.interval <= 0 {
		return errors.New("fixed ownership retention seam is incomplete")
	}
	var nextRelease time.Time
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		settled, pidfd := seam.state()
		if settled && (nextRelease.IsZero() || !time.Now().Before(nextRelease)) {
			releaseCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := seam.release(releaseCtx)
			cancel()
			if err == nil {
				return nil
			}
			nextRelease = time.Now().Add(seam.interval)
		} else if !settled && pidfd >= 0 {
			_ = seam.signal(pidfd)
		}
		timer := time.NewTimer(seam.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// retainCheckpointFixedLaunch deliberately parks this supervisor until the
// owned waiter proves exact reap, Commit is settled, and terminal filesystem
// cleanup succeeds. If the OS forcibly kills this process, open descriptors
// disappear but staged files remain persistently charged; no crash collector
// or current-capacity claim is implied.
func retainCheckpointFixedLaunch(launch *CheckpointControlledLaunch) {
	seam := checkpointFixedRetentionSeam{
		state: func() (bool, int) {
			launch.mu.Lock()
			defer launch.mu.Unlock()
			waitDone := false
			if launch.waitDone != nil {
				select {
				case <-launch.waitDone:
					waitDone = true
				default:
				}
			}
			waitSettled := launch.started && waitDone && launch.reaped
			abortSettled := !launch.started && (launch.aborted || launch.failedStart) && (!launch.childCreated || launch.reaped)
			return (waitSettled || abortSettled) && launch.terminal && !launch.committing && launch.commitDone == nil, launch.pidfd
		},
		signal: func(pidfd int) error {
			launch.mu.Lock()
			defer launch.mu.Unlock()
			if pidfd < 0 || launch.pidfd != pidfd {
				return errors.New("retained child pidfd authority changed")
			}
			return killCheckpointChildPlatform(pidfd)
		},
		release:  launch.ReleaseTerminal,
		interval: time.Second,
	}
	_ = retainCheckpointFixedOwnership(context.Background(), seam)
}

func retainCheckpointPreparedModel(model *CheckpointPreparedModel) {
	if model == nil {
		return
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := model.Discard(ctx)
		cancel()
		if err == nil {
			return
		}
		time.Sleep(time.Second)
	}
}

func validateCheckpointFixedStartupPair(first, second checkpointFixedStartupSample, spec CheckpointLaunchPlan, stagedExecutablePath string, pid, supervisorPID int) error {
	if pid <= 1 || supervisorPID <= 1 || pid == supervisorPID {
		return errors.New("fixed startup process identities are invalid")
	}
	if first.unit != second.unit || first.binding != second.binding || first.identity != second.identity || first.childParent != second.childParent || first.supervisorStartTicks != second.supervisorStartTicks || first.childCgroup != second.childCgroup || first.supervisorCgroup != second.supervisorCgroup || first.placement.Backend != second.placement.Backend || first.placement.PhysicalIdentity != second.placement.PhysicalIdentity || first.placement.ChildMaskUUID != second.placement.ChildMaskUUID || first.placement.RuntimeDeviceToken != second.placement.RuntimeDeviceToken || first.placement.RuntimeVersion != second.placement.RuntimeVersion || first.footprint.LayersGPU != second.footprint.LayersGPU || first.footprint.LayersTotal != second.footprint.LayersTotal {
		return errors.New("fixed startup identity or layer policy changed between fresh observations")
	}
	if err := validateCheckpointPlacementJoin(spec, first.placement); err != nil {
		return err
	}
	if err := validateCheckpointPlacementJoin(spec, second.placement); err != nil {
		return err
	}
	if err := validateCheckpointOffloadEvidence(spec.Placement.OffloadPolicy, first.footprint, spec.Placement.MinGPUBytes, spec.Placement.MaxHostRSSBytes); err != nil {
		return err
	}
	if err := validateCheckpointOffloadEvidence(spec.Placement.OffloadPolicy, second.footprint, spec.Placement.MinGPUBytes, spec.Placement.MaxHostRSSBytes); err != nil {
		return err
	}
	if stagedExecutablePath == "" || first.unit.MainPID != pid || first.unit.Active != "activating" || first.unit.Sub == "" || first.unit.Sub == "running" || !checkpointInvocationIDRE.MatchString(first.unit.Invocation) || first.unit.Invocation == strings.Repeat("0", 32) || !validCheckpointCgroupPath(first.unit.ControlGroup) {
		return errors.New("manager startup identity is not a valid activating fixed unit")
	}
	if first.childParent != supervisorPID || first.supervisorStartTicks == 0 || first.childCgroup != first.unit.ControlGroup || first.supervisorCgroup != first.unit.ControlGroup {
		return errors.New("fixed worker and supervisor parent/cgroup association is invalid")
	}
	b, i := first.binding, first.identity
	if b.PID != pid || b.ServiceUnit != checkpointIdentityServiceUnit || b.UnitAssociation != "label-only-unverified" || b.ActualAlias != spec.Alias || b.Endpoint != "http://"+net.JoinHostPort(spec.Endpoint.Host, strconv.Itoa(spec.Endpoint.Port)) || !strings.EqualFold(b.ArtifactSHA256, spec.Model.SHA256) || b.ArtifactSize != spec.Model.Bytes || !strings.EqualFold(b.ExecutableSHA256, spec.Executable.SHA256) || b.ExecutablePath != stagedExecutablePath || !checkpointSHA256RE.MatchString(b.BindingSHA256) || !checkpointSHA256RE.MatchString(b.Nonce) {
		return errors.New("authenticated receipt is not bound to the fixed local plan")
	}
	if i.PID != pid || i.ServiceUnit != checkpointIdentityServiceUnit || i.Fingerprint == "" || i.BootID != b.BootID || i.ProcessStartTicks != b.ProcessStartTicks || i.ListenerSocketInode != b.ListenerSocketInode || i.Endpoint != b.Endpoint || i.ExecutablePath != stagedExecutablePath || i.ExecutablePath != b.ExecutablePath || !strings.EqualFold(i.ExecutableSHA256, b.ExecutableSHA256) || i.ModelPath != b.ArtifactPath || i.ModelDevice != b.ArtifactDevice || i.ModelInode != b.ArtifactInode || i.ModelSize != b.ArtifactSize || !strings.EqualFold(i.ModelSHA256, b.ArtifactSHA256) {
		return errors.New("fresh local process identity differs from the authenticated receipt")
	}
	return nil
}

func (s *checkpointFixedSupervisor) cancelStarted(ctx context.Context) error {
	s.mu.Lock()
	if s.settled || s.launch == nil {
		s.mu.Unlock()
		return nil
	}
	launch := s.launch
	s.mu.Unlock()
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
	}
	cleanupErr := cleanupCheckpointFixedOwnedChild(ctx, func(cleanupCtx context.Context) (bool, error) {
		waitCtx, stopWait := context.WithCancel(cleanupCtx)
		stopWait()
		waitErr := launch.WaitContext(waitCtx)
		stopWait()
		launch.mu.Lock()
		reaped := launch.reaped
		launch.mu.Unlock()
		if reaped {
			return true, nil
		}
		return reaped, waitErr
	}, func(cleanupCtx context.Context) error {
		err := launch.ReleaseTerminal(cleanupCtx)
		if err == nil {
			s.mu.Lock()
			s.settled = true
			s.mu.Unlock()
		}
		return err
	})
	return cleanupErr
}

func fixedCheckpointCommand(executable string, args []string) *exec.Cmd {
	cmd := exec.Command(executable, args...)
	// The child cannot inherit NOTIFY_SOCKET. NotifyAccess=all trusts only the
	// root-owned executable pinned by this local plan; this is not an adversarial
	// root boundary.
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	return cmd
}

func fixedCheckpointPlacementCommand(executable string, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (*exec.Cmd, *checkpointRuntimeLog, error) {
	args, err := fixedCheckpointPlacementArguments(plan)
	if err != nil {
		return nil, nil, err
	}
	if err := validateCheckpointPlacementJoin(plan, placement); err != nil {
		return nil, nil, err
	}
	cmd := fixedCheckpointCommand(executable, args)
	cmd.Env = runtimeCheckpointChildEnvironment(placement.ChildMaskUUID)
	if plan.RuntimeOptions != nil {
		cmd.Env = append(cmd.Env, "LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=1")
	}
	log := &checkpointRuntimeLog{}
	cmd.Stdout, cmd.Stderr = log, log
	return cmd, log, nil
}
