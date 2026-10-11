package nodeagent

// This file contains a deliberately standalone custody primitive. A successful
// receipt is evidence for a controlled launch only; it does not advertise
// checkpoint capability or displace a running model.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const custodyMaxArtifactBytes int64 = 256 << 30
const custodyMaxReserveBytes int64 = 1 << 30
const custodyMaxStagingBytes int64 = 512 << 30
const custodyMaxReceiptCount = 4096
const custodyMaxReceiptBytes = 1 << 20
const custodyMaxReceiptVerifyBytes = 16 << 20
const custodyMaxLiveVerifyCandidates = 2
const custodyMaxExecutableVerifyBytes = 256 << 20

var custodyDigestRE = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

type CheckpointCustodyConfig struct {
	Root             string
	MaxArtifactBytes int64
	MaxStagingBytes  int64
	ReserveBytes     int64
}

type CheckpointCustodySource struct {
	Path           string
	ApprovedSHA256 string
	ExpectedBytes  int64
}

type CheckpointCustodyStore struct {
	root                            string
	maxBytes                        int64
	maxStagingBytes                 int64
	reserve                         int64
	rootDevice, rootInode           uint64
	modelsDevice, modelsInode       uint64
	launchersDevice, launchersInode uint64
	receiptsDevice, receiptsInode   uint64
	gateOnce                        sync.Once
	gate                            chan struct{}
	verifyTestAfterReceiptRead      func(string)
	syncTest                        func(string) error
	reuseCopyBytesTest              func(int64)
	reuseAfterCopyTest              func(string) error
	reuseRecordBeforePublishTest    func(string) error
	reuseModelSyncTest              func() error
	reuseRecordSyncTest             func() error
	cleanupBeforeCaptureTest        func(string, string)
	cleanupAfterCaptureTest         func(string, string)
	beginAfterStageTest             func(string) error
	stageExecutableAfterPinTest     func(string) error
}

type custodyCleanupState struct {
	CaptureName string
	Captured    bool
	Removed     bool
	Synced      bool
}

type CheckpointPreparedModel struct {
	store                   *CheckpointCustodyStore
	path                    string
	identity                custodySourceIdentity
	reusable                bool
	reuseKey                string
	modelPin                *os.File
	used                    bool
	beginning               bool
	beginFailed             bool
	discarded               bool
	discardCleanup          custodyCleanupState
	failedExecutablePath    string
	failedExecutableFD      *os.File
	failedExecutableCleanup custodyCleanupState
	lifecycleOnce           sync.Once
	lifecycleGate           chan struct{}
	mu                      sync.Mutex
}

// CheckpointControlledLaunch is an opaque, single-use launch authority. Its
// command is started only by Start, so a caller cannot attach an old PID.
type CheckpointControlledLaunch struct {
	store                    *CheckpointCustodyStore
	model                    *CheckpointPreparedModel
	cmd                      *exec.Cmd
	modelFD                  *os.File
	executableFD             *os.File
	executablePath           string
	permit                   *struct{}
	pidfd                    int
	commitPIDFD              int
	bootID                   string
	preBootNS                int64
	startBootNS              int64
	startedBootNS            int64
	nonce                    string
	endpoint                 string
	unit                     string
	alias                    string
	expectedExecutableSHA256 string
	started                  bool
	childCreated             bool
	committed                bool
	commitAttempted          bool
	waitStarted              bool
	committing               bool
	aborted                  bool
	aborting                 bool
	failedStart              bool
	waitDone                 chan struct{}
	waitErr                  error
	commitDone               chan struct{}
	commitCancel             context.CancelFunc
	// Deterministic cancellation seam used only by the Linux custody test.
	commitTestBarrier             <-chan struct{}
	commitTestEntered             chan<- struct{}
	commitAfterPublishTestBarrier <-chan struct{}
	commitAfterPublishTestEntered chan<- struct{}
	commitCleanupTestBarrier      <-chan struct{}
	commitCleanupTestEntered      chan<- struct{}
	receiptPinFailureTest         bool
	waitUnknownTest               bool
	controlledSource              bool
	controlledArgv                []string
	controlledModelArgument       string
	controlledExecutableIdentity  custodySourceIdentity
	controlledExecutablePinned    bool
	receiptPin                    *os.File
	receiptRaw                    []byte
	receiptDevice, receiptInode   uint64
	receiptPublished              bool
	receiptSettled                bool
	receiptCleanup                custodyCleanupState
	modelCleanup                  custodyCleanupState
	executableCleanup             custodyCleanupState
	executableCleanupGateOnce     sync.Once
	executableCleanupGate         chan struct{}
	terminal                      bool
	reaped                        bool
	released                      bool
	releaseOnce                   sync.Once
	releaseGate                   chan struct{}
	mu                            sync.Mutex
}

type CheckpointCustodyLaunchRequest struct {
	Command *exec.Cmd
	// Exactly one argument must equal {CHECKPOINT_MODEL}; Start substitutes the
	// private immutable path at that position.
	Endpoint                 string
	ServiceUnit              string
	ActualAlias              string
	ExpectedExecutableSHA256 string
}

// CheckpointCustodyVerification is returned only after a local receipt,
// signature, live child/socket/executable/mapping, and fs-verity are checked.
// UnitAssociation remains label-only until a fixed launcher supplies external
// systemd invocation/MainPID evidence in its integration layer. BindingSHA256
// hashes the JSON form of this value with BindingSHA256 left empty.
type CheckpointCustodyVerification struct {
	EvidenceKind           string
	ModelArgument          string
	ArgvSHA256             string
	BindingSHA256          string
	Nonce                  string
	Endpoint               string
	ServiceUnit            string
	UnitAssociation        string
	BootID                 string
	PID                    int
	ProcessStartTicks      uint64
	ListenerSocketInode    uint64
	ExecutablePath         string
	ExecutableSHA256       string
	ActualAlias            string
	ArtifactPath           string
	ArtifactDevice         uint64
	ArtifactInode          uint64
	ArtifactSize           int64
	ArtifactSHA256         string
	VerityDigest           string
	ExecutableDevice       uint64
	ExecutableInode        uint64
	ExecutableSize         int64
	ExecutableVerityDigest string
	PrelaunchBootNS        int64
	StartBootNS            int64
	StartedBootNS          int64
}

type custodySourceIdentity struct {
	CanonicalPath string `json:"canonical_path"`
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	VerityDigest  string `json:"verity_digest"`
}

const custodyReuseRecordVersion = 1
const custodyMaxReuseRecordBytes = 8192

type custodyReuseRecord struct {
	Version      int                   `json:"version"`
	KeyID        string                `json:"key_id"`
	Key          string                `json:"key"`
	SourcePath   string                `json:"source_path"`
	SourceSHA256 string                `json:"source_sha256"`
	SourceSize   int64                 `json:"source_size"`
	Staged       custodySourceIdentity `json:"staged"`
}

type custodySignedReuseRecord struct {
	Record    custodyReuseRecord `json:"record"`
	Signature string             `json:"signature"`
}

type custodyReceipt struct {
	Version          int                    `json:"version"`
	EvidenceKind     string                 `json:"evidence_kind,omitempty"`
	ModelArgument    string                 `json:"model_argument,omitempty"`
	ArgvSHA256       string                 `json:"argv_sha256,omitempty"`
	KeyID            string                 `json:"key_id"`
	Nonce            string                 `json:"nonce"`
	BootID           string                 `json:"boot_id"`
	PrelaunchBootNS  int64                  `json:"prelaunch_boot_ns"`
	StartBootNS      int64                  `json:"start_boot_ns"`
	StartedBootNS    int64                  `json:"started_boot_ns"`
	PID              int                    `json:"pid"`
	StartTicks       uint64                 `json:"start_ticks"`
	ServiceUnit      string                 `json:"service_unit"`
	UnitAssociation  string                 `json:"unit_association"`
	Endpoint         string                 `json:"endpoint"`
	SocketInode      uint64                 `json:"socket_inode"`
	ExecutablePath   string                 `json:"executable_path"`
	ExecutableSHA256 string                 `json:"executable_sha256"`
	ActualAlias      string                 `json:"actual_alias"`
	Source           custodySourceIdentity  `json:"source"`
	Executable       *custodySourceIdentity `json:"executable,omitempty"`
}

type custodySignedReceipt struct {
	Receipt   custodyReceipt `json:"receipt"`
	Signature string         `json:"signature"`
}

func OpenCheckpointCustodyStore(cfg CheckpointCustodyConfig) (*CheckpointCustodyStore, error) {
	if cfg.Root == "" || !filepath.IsAbs(cfg.Root) || strings.Contains(cfg.Root, "..") {
		return nil, errors.New("custody root must be an absolute canonical path")
	}
	if cfg.MaxArtifactBytes <= 0 || cfg.MaxArtifactBytes > custodyMaxArtifactBytes || cfg.MaxStagingBytes <= 0 || cfg.MaxStagingBytes > custodyMaxStagingBytes || cfg.ReserveBytes < 0 || cfg.ReserveBytes > custodyMaxReserveBytes {
		return nil, errors.New("custody byte and reserve quotas are invalid")
	}
	store, err := openCheckpointCustodyPlatform(cfg)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.ensureKey(ctx); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *CheckpointCustodyStore) Prepare(ctx context.Context, src CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	if s == nil || ctx == nil || !custodyDigestRE.MatchString(src.ApprovedSHA256) || src.ExpectedBytes <= 0 || src.ExpectedBytes > s.maxBytes {
		return nil, errors.New("custody source request is invalid or exceeds configured quota")
	}
	return prepareCheckpointCustodyPlatform(ctx, s, src)
}

// PrepareReusable prepares an authenticated, immutable cache entry keyed by
// the original canonical source path, approved digest, and exact source size.
// The returned model is still a fresh, single-use authority for one launch.
func (s *CheckpointCustodyStore) PrepareReusable(ctx context.Context, src CheckpointCustodySource) (*CheckpointPreparedModel, error) {
	if s == nil || ctx == nil || !custodyDigestRE.MatchString(src.ApprovedSHA256) || src.ExpectedBytes <= 0 || src.ExpectedBytes > s.maxBytes {
		return nil, errors.New("reusable custody source request is invalid or exceeds configured quota")
	}
	return prepareReusableCheckpointCustodyPlatform(ctx, s, src)
}

func (s *CheckpointCustodyStore) Begin(model *CheckpointPreparedModel, req CheckpointCustodyLaunchRequest) (*CheckpointControlledLaunch, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return s.BeginContext(ctx, model, req)
}

// BeginContext bounds local coordination, executable staging, and permit creation.
func (s *CheckpointCustodyStore) BeginContext(ctx context.Context, model *CheckpointPreparedModel, req CheckpointCustodyLaunchRequest) (*CheckpointControlledLaunch, error) {
	return s.beginContext(ctx, model, req, false)
}

// beginFixedContext is the only path that can attach controlled-source
// provenance. It is private to the fixed launcher and still retains the
// opaque, single-use launch permit produced by the common custody machinery.
func (s *CheckpointCustodyStore) beginFixedContext(ctx context.Context, model *CheckpointPreparedModel, req CheckpointCustodyLaunchRequest) (*CheckpointControlledLaunch, error) {
	return s.beginContext(ctx, model, req, true)
}

func (s *CheckpointCustodyStore) beginContext(ctx context.Context, model *CheckpointPreparedModel, req CheckpointCustodyLaunchRequest, controlledSource bool) (*CheckpointControlledLaunch, error) {
	if s == nil || ctx == nil || model == nil || model.store != s || req.Command == nil || req.Command.Process != nil || req.Command.ProcessState != nil || len(req.Command.ExtraFiles) != 0 || len(req.Command.Args) == 0 || req.Endpoint == "" || len(req.Endpoint) > 512 || req.ServiceUnit != checkpointIdentityServiceUnit || req.ActualAlias == "" || len(req.ActualAlias) > 512 || !custodyDigestRE.MatchString(req.ExpectedExecutableSHA256) {
		return nil, errors.New("controlled launch request is incomplete")
	}
	if req.Command.Args[0] == "" {
		return nil, errors.New("controlled launch argv0 must be non-empty")
	}
	modelArg := -1
	for i := 1; i < len(req.Command.Args); i++ {
		arg := req.Command.Args[i]
		if arg == "-m" || arg == "--model" {
			if modelArg >= 0 || i+1 >= len(req.Command.Args) || req.Command.Args[i+1] != "{CHECKPOINT_MODEL}" {
				return nil, errors.New("controlled launch must select the prepared model exactly once")
			}
			modelArg = i + 1
			i++
			continue
		}
		lower := strings.ToLower(arg)
		if arg == "{CHECKPOINT_MODEL}" || strings.HasPrefix(lower, "--model=") || strings.HasPrefix(lower, "--model-") || strings.HasPrefix(lower, "--models") || strings.HasPrefix(lower, "--config") || strings.HasPrefix(lower, "--router") || strings.HasPrefix(lower, "-m") {
			return nil, errors.New("controlled launch contains an ambiguous model or configuration override")
		}
	}
	if modelArg < 0 {
		return nil, errors.New("controlled launch command must name the prepared model with -m or --model")
	}
	unlockLifecycle, err := model.acquireLifecycle(ctx)
	if err != nil {
		return nil, err
	}
	defer unlockLifecycle()
	model.mu.Lock()
	if model.used {
		model.mu.Unlock()
		return nil, errors.New("prepared source has already been used")
	}
	if model.discarded {
		model.mu.Unlock()
		return nil, errors.New("prepared source has already been discarded")
	}
	if err := ctx.Err(); err != nil {
		model.mu.Unlock()
		return nil, err
	}
	model.used = true
	model.beginning = true
	model.mu.Unlock()
	cmdCopy := *req.Command
	cmdCopy.Args = append([]string(nil), req.Command.Args...)
	cmdCopy.Env = append([]string(nil), req.Command.Env...)
	if req.Command.SysProcAttr != nil {
		attr := *req.Command.SysProcAttr
		cmdCopy.SysProcAttr = &attr
	}
	req.Command = &cmdCopy
	launch, err := beginCheckpointCustodyPlatform(ctx, s, model, req)
	if err == nil && launch != nil {
		launch.controlledSource = controlledSource
	}
	model.mu.Lock()
	model.beginning = false
	model.beginFailed = err != nil
	model.mu.Unlock()
	return launch, err
}

// Discard removes an unused prepared source, or one whose Begin call returned
// without producing a launch permit. It never makes a consumed source reusable.
func (m *CheckpointPreparedModel) Discard(ctx context.Context) error {
	if m == nil || ctx == nil || m.store == nil {
		return errors.New("prepared source and context are required")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	unlockLifecycle, err := m.acquireLifecycle(bounded)
	if err != nil {
		return err
	}
	defer unlockLifecycle()
	m.mu.Lock()
	if m.discarded {
		m.mu.Unlock()
		return nil
	}
	if m.beginning || (m.used && !m.beginFailed) {
		m.mu.Unlock()
		return errors.New("prepared source is consumed by a launch")
	}
	m.mu.Unlock()
	if err := bounded.Err(); err != nil {
		return err
	}
	if m.reusable {
		// Cache model bytes are retained, while a failed Begin may have staged an
		// exact owned executable that still needs retry-safe terminal cleanup.
		if err := discardReusableCheckpointModelPlatform(bounded, m); err != nil {
			return err
		}
		m.mu.Lock()
		if m.modelPin != nil {
			_ = m.modelPin.Close()
			m.modelPin = nil
		}
		m.discarded = true
		m.mu.Unlock()
		return nil
	}
	if err := discardCheckpointCustodySourcePlatform(bounded, m); err != nil {
		return err
	}
	m.mu.Lock()
	m.discarded = true
	if m.modelPin != nil {
		_ = m.modelPin.Close()
		m.modelPin = nil
	}
	m.mu.Unlock()
	return nil
}

func (m *CheckpointPreparedModel) acquireLifecycle(ctx context.Context) (func(), error) {
	if m == nil || ctx == nil {
		return nil, errors.New("prepared source and lifecycle context are required")
	}
	m.lifecycleOnce.Do(func() {
		m.lifecycleGate = make(chan struct{}, 1)
		m.lifecycleGate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.lifecycleGate:
		return func() { m.lifecycleGate <- struct{}{} }, nil
	}
}

func custodyQuotaFits(used, requested, reserve, limit int64) bool {
	if used < 0 || requested < 0 || reserve < 0 || limit < 0 || used > limit {
		return false
	}
	remaining := limit - used
	if requested > remaining {
		return false
	}
	remaining -= requested
	return reserve <= remaining
}

func (l *CheckpointControlledLaunch) Start() (startErr error) {
	if l == nil || l.permit == nil {
		return errors.New("controlled launch permit is invalid")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started || l.committed || l.aborted || l.aborting || l.failedStart {
		return errors.New("controlled launch is single use")
	}
	defer func() {
		if startErr != nil && !l.started {
			l.failedStart = true
			if !l.childCreated || l.reaped {
				if l.modelFD != nil {
					_ = l.modelFD.Close()
					l.modelFD = nil
				}
				if l.cmd != nil {
					l.cmd.ExtraFiles = nil
				}
				l.terminal = true
			}
		}
	}()
	for i := 1; i < len(l.cmd.Args); i++ {
		arg := l.cmd.Args[i]
		if arg == "{CHECKPOINT_MODEL}" {
			l.cmd.Args[i] = "/proc/self/fd/4"
		}
	}
	if !containsExact(l.cmd.Args, "/proc/self/fd/4") {
		return errors.New("prepared immutable descriptor is absent from launch arguments")
	}
	if l.controlledSource {
		modelArgument := ""
		for i, arg := range l.cmd.Args {
			if arg == "/proc/self/fd/4" {
				if modelArgument != "" || i == 0 || l.cmd.Args[i-1] != "-m" && l.cmd.Args[i-1] != "--model" {
					return errors.New("controlled source launch must use exactly one fixed descriptor model argument")
				}
				modelArgument = arg
			}
		}
		if len(l.cmd.Args) == 0 || len(l.cmd.Args) > 128 {
			return errors.New("controlled fixed argv exceeds its bounds")
		}
		argvBytes, err := json.Marshal(l.cmd.Args)
		if err != nil || len(argvBytes) > 16<<10 {
			return errors.New("controlled fixed argv identity exceeds its bounds")
		}
		l.controlledArgv = append([]string(nil), l.cmd.Args...)
		l.controlledModelArgument = modelArgument
		_ = argvBytes // bounds and snapshots the exact fixed argument vector before exec.
	}
	if len(l.cmd.ExtraFiles) != 2 {
		return errors.New("controlled launch descriptor set is incomplete")
	}
	if err := validatePreparedCheckpointPlatform(l.model, l.cmd.ExtraFiles[1]); err != nil {
		return err
	}
	if err := validateCheckpointLaunchExecutablePlatform(l.executablePath, l.expectedExecutableSHA256, l.cmd.ExtraFiles[0]); err != nil {
		return err
	}
	if l.startBootNS, _ = checkpointBootTimeNS(); l.startBootNS <= 0 {
		return errors.New("CLOCK_BOOTTIME unavailable before controlled process start")
	}
	if err := l.cmd.Start(); err != nil {
		return err
	}
	l.childCreated = true
	if l.modelFD != nil {
		_ = l.modelFD.Close()
		l.modelFD = nil
	}
	l.cmd.ExtraFiles = nil
	pidfd, err := retainCheckpointChildPlatform(l.cmd.Process.Pid)
	if err != nil {
		_ = l.cmd.Process.Kill()
		_ = l.cmd.Wait()
		l.reaped = l.cmd.ProcessState != nil
		return err
	}
	l.pidfd = pidfd
	startedBoot, timeErr := checkpointBootTimeNS()
	l.startedBootNS = startedBoot
	if timeErr != nil || l.startedBootNS < l.startBootNS {
		_ = killCheckpointChildPlatform(l.pidfd)
		_ = l.cmd.Wait()
		l.reaped = l.cmd.ProcessState != nil
		if l.reaped {
			closeCheckpointChildPlatform(l.pidfd)
			l.pidfd = -1
		}
		if timeErr != nil {
			return fmt.Errorf("read CLOCK_BOOTTIME after controlled process start: %w", timeErr)
		}
		return errors.New("CLOCK_BOOTTIME bracket moved backwards")
	}
	l.started = true
	return nil
}

// WaitContext reaps only this launch's child and closes its retained pidfd.
// If the context expires it kills the child through pidfd and completes reaping.
func (l *CheckpointControlledLaunch) WaitContext(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("controlled launch and context are required")
	}
	l.mu.Lock()
	if !l.started || l.cmd == nil || l.waitStarted {
		l.mu.Unlock()
		return errors.New("controlled child is not waitable or was already reaped")
	}
	l.waitStarted = true
	l.waitDone = make(chan struct{})
	done := l.waitDone
	commitDone := l.commitDone
	commitCancel := l.commitCancel
	cmd := l.cmd
	go func() {
		err := cmd.Wait()
		l.mu.Lock()
		l.waitErr = err
		l.reaped = cmd.ProcessState != nil
		if l.waitUnknownTest {
			l.reaped = false
		}
		if l.reaped {
			if l.pidfd >= 0 {
				closeCheckpointChildPlatform(l.pidfd)
				l.pidfd = -1
			}
		}
		if l.reaped && l.commitDone == nil && !l.committing {
			l.terminal = true
		}
		close(done)
		l.mu.Unlock()
	}()
	l.mu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		l.mu.Lock()
		if commitCancel != nil {
			commitCancel()
		}
		// Keep the launch lock while signaling: the waiter closes pidfd under
		// this lock, so the descriptor cannot be reused for another object.
		if l.pidfd >= 0 {
			_ = killCheckpointChildPlatform(l.pidfd)
		}
		l.mu.Unlock()
	}
	if ctx.Err() != nil {
		l.mu.Lock()
		if commitCancel != nil {
			commitCancel()
		}
		if l.pidfd >= 0 {
			_ = killCheckpointChildPlatform(l.pidfd)
		}
		l.mu.Unlock()
	}
	if commitDone != nil {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-commitDone:
		case <-ctx.Done():
			l.mu.Lock()
			if commitCancel != nil {
				commitCancel()
			}
			if l.pidfd >= 0 {
				_ = killCheckpointChildPlatform(l.pidfd)
			}
			l.mu.Unlock()
			select {
			case <-commitDone:
			case <-timer.C:
				return errors.New("controlled commit did not stop within bounded cleanup interval")
			}
		case <-timer.C:
			return errors.New("controlled commit did not finish within bounded interval")
		}
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		return errors.New("controlled child did not exit within bounded cleanup interval")
	}
	l.mu.Lock()
	if l.waitDone == done && l.waitErr != nil { /* exact reap still establishes terminal ownership */
	}
	if !l.reaped {
		l.mu.Unlock()
		return errors.New("controlled process reap could not be confirmed")
	}
	l.terminal = true
	waitErr := l.waitErr
	l.mu.Unlock()
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	cleanupErr := l.cleanupExecutableBounded(cleanupCtx)
	cleanupCancel()
	if cleanupErr != nil {
		return errors.Join(waitErr, cleanupErr)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return waitErr
}

// cleanupExecutableBounded isolates filesystem cleanup from the exact reaper.
// If a filesystem call outlives ctx, the cleanup retains its inode pin and gate;
// a later terminal release can retry after that operation finishes.
func (l *CheckpointControlledLaunch) cleanupExecutableBounded(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("controlled launch cleanup context is required")
	}
	l.executableCleanupGateOnce.Do(func() { l.executableCleanupGate = make(chan struct{}, 1) })
	gate := l.executableCleanupGate
	done := make(chan error, 1)
	go func() {
		select {
		case gate <- struct{}{}:
		case <-ctx.Done():
			done <- ctx.Err()
			return
		}
		defer func() { <-gate }()
		l.mu.Lock()
		fd, path := l.executableFD, l.executablePath
		l.mu.Unlock()
		if fd == nil {
			done <- nil
			return
		}
		err := releaseCheckpointExecutableContextPlatform(ctx, l.store, path, fd, &l.executableCleanup)
		if err == nil {
			_ = fd.Close()
			l.mu.Lock()
			if l.executableFD == fd {
				l.executableFD = nil
			}
			l.mu.Unlock()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Abort releases a permit that has not started a child. Started children must
// be reaped with WaitContext so cleanup retains exact process authority.
func (l *CheckpointControlledLaunch) Abort() error {
	if l == nil || l.permit == nil {
		return errors.New("controlled launch is required")
	}
	l.mu.Lock()
	if l.started || l.waitStarted || (l.childCreated && !l.reaped) {
		l.mu.Unlock()
		return errors.New("started controlled child must be reaped with WaitContext")
	}
	if l.aborted && l.executableFD == nil {
		l.mu.Unlock()
		return nil
	}
	l.aborting = true
	if l.cmd != nil {
		l.cmd.ExtraFiles = nil
	}
	if l.modelFD != nil {
		_ = l.modelFD.Close()
		l.modelFD = nil
	}
	l.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := l.cleanupExecutableBounded(ctx)
	cancel()
	l.mu.Lock()
	l.aborting = false
	l.aborted = true
	l.terminal = true
	l.mu.Unlock()
	return err
}

// ReleaseTerminal reclaims the exact staged model and authenticated receipt
// only after Abort or exact child reap and settled Commit establish ownership.
func (l *CheckpointControlledLaunch) ReleaseTerminal(ctx context.Context) error {
	if l == nil || ctx == nil || l.store == nil || l.model == nil {
		return errors.New("controlled launch and context are required")
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	l.releaseOnce.Do(func() {
		l.releaseGate = make(chan struct{}, 1)
		l.releaseGate <- struct{}{}
	})
	select {
	case <-bounded.Done():
		return bounded.Err()
	case <-l.releaseGate:
	}
	done := make(chan error, 1)
	go func() {
		defer func() { l.releaseGate <- struct{}{} }()
		l.mu.Lock()
		if !l.terminal || l.aborting || l.committing || l.commitDone != nil || (l.started && !l.reaped && !l.aborted) {
			l.mu.Unlock()
			done <- errors.New("controlled launch has no settled terminal ownership")
			return
		}
		if l.committed && !l.reaped {
			l.mu.Unlock()
			done <- errors.New("committed child must be exactly reaped before source release")
			return
		}
		if l.released {
			l.mu.Unlock()
			done <- nil
			return
		}
		l.mu.Unlock()
		if err := releaseCheckpointCustodyTerminalPlatform(bounded, l); err != nil {
			done <- err
			return
		}
		l.mu.Lock()
		if l.pidfd >= 0 {
			closeCheckpointChildPlatform(l.pidfd)
			l.pidfd = -1
		}
		l.released = true
		l.mu.Unlock()
		done <- nil
	}()
	select {
	case err := <-done:
		return err
	case <-bounded.Done():
		return bounded.Err()
	}
}

// releaseUnstartedLocked supports the package's zero-value cleanup oracle and
// is retained for internal callers that already hold l.mu. Production Abort
// uses cleanupExecutableBounded so its caller can return on its cleanup budget.
func (l *CheckpointControlledLaunch) releaseUnstartedLocked() error {
	if l == nil {
		return nil
	}
	if l.cmd != nil {
		l.cmd.ExtraFiles = nil
	}
	if l.modelFD != nil {
		_ = l.modelFD.Close()
		l.modelFD = nil
	}
	if l.executableFD == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err := releaseCheckpointExecutableContextPlatform(ctx, l.store, l.executablePath, l.executableFD, &l.executableCleanup)
	cancel()
	if err == nil {
		_ = l.executableFD.Close()
		l.executableFD = nil
	}
	return err
}

func (l *CheckpointControlledLaunch) Commit(ctx context.Context) error {
	if l == nil || ctx == nil {
		return errors.New("controlled launch and context are required")
	}
	l.mu.Lock()
	if !l.started || l.committed || l.commitAttempted || l.committing || l.cmd.Process == nil {
		l.mu.Unlock()
		return errors.New("only a started, uncommitted controlled child can be committed")
	}
	if l.waitStarted {
		l.mu.Unlock()
		return errors.New("controlled child was already reaped before custody commit")
	}
	if l.pidfd < 0 {
		l.mu.Unlock()
		return errors.New("controlled child pidfd authority is unavailable")
	}
	commitPIDFD, err := duplicateCheckpointChildPlatform(l.pidfd)
	if err != nil {
		l.mu.Unlock()
		return err
	}
	commitCtx, cancel := context.WithCancel(ctx)
	l.commitAttempted = true
	l.committing = true
	l.commitPIDFD = commitPIDFD
	l.commitCancel = cancel
	l.commitDone = make(chan struct{})
	commitDone := l.commitDone
	l.mu.Unlock()
	err = commitCheckpointCustodyPlatform(commitCtx, l)
	if l.commitAfterPublishTestEntered != nil {
		close(l.commitAfterPublishTestEntered)
	}
	if l.commitAfterPublishTestBarrier != nil {
		<-l.commitAfterPublishTestBarrier
	}
	commitContextErr := commitCtx.Err()
	cancel()
	l.mu.Lock()
	if l.commitPIDFD >= 0 {
		closeCheckpointChildPlatform(l.commitPIDFD)
		l.commitPIDFD = -1
	}
	l.committing = false
	l.commitCancel = nil
	if err == nil && (l.waitStarted || commitContextErr != nil) {
		err = errors.New("controlled launch was canceled or reaped before custody commit completed")
	}
	if err == nil {
		l.committed = true
	}
	l.mu.Unlock()
	if err != nil {
		if l.commitCleanupTestEntered != nil {
			close(l.commitCleanupTestEntered)
		}
		if l.commitCleanupTestBarrier != nil {
			<-l.commitCleanupTestBarrier
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		cleanupDone := make(chan error, 1)
		finish := func() {
			l.mu.Lock()
			if l.commitDone == commitDone {
				l.commitDone = nil
				if l.reaped {
					l.terminal = true
				}
				close(commitDone)
			}
			l.mu.Unlock()
		}
		go func() {
			cleanupErr := removeCheckpointCustodyReceiptPlatform(cleanupCtx, l)
			cleanupCancel()
			finish()
			cleanupDone <- cleanupErr
		}()
		select {
		case cleanupErr := <-cleanupDone:
			if cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			return err
		case <-cleanupCtx.Done():
			select {
			case cleanupErr := <-cleanupDone:
				if cleanupErr != nil {
					err = errors.Join(err, cleanupErr)
				}
				return err
			default:
			}
			return errors.Join(err, fmt.Errorf("published receipt cleanup remains pending after bounded interval: %w", cleanupCtx.Err()))
		}
	}
	l.mu.Lock()
	if l.commitDone == commitDone {
		l.commitDone = nil
		if l.reaped {
			l.terminal = true
		}
		close(commitDone)
	}
	l.mu.Unlock()
	return err
}

func (s *CheckpointCustodyStore) Verify(ctx context.Context, endpoint, unit string) (bool, error) {
	if s == nil || ctx == nil {
		return false, errors.New("custody store and context are required")
	}
	return verifyCheckpointCustodyPlatform(ctx, s, endpoint, unit)
}

func (s *CheckpointCustodyStore) VerifyBinding(ctx context.Context, endpoint, unit string) (CheckpointCustodyVerification, bool, error) {
	if s == nil || ctx == nil {
		return CheckpointCustodyVerification{}, false, errors.New("custody store and context are required")
	}
	return verifyCheckpointCustodyBindingPlatform(ctx, s, endpoint, unit)
}

func (s *CheckpointCustodyStore) acquire(ctx context.Context) (func(), error) {
	if s == nil || ctx == nil {
		return nil, errors.New("custody store and context are required")
	}
	s.gateOnce.Do(func() {
		s.gate = make(chan struct{}, 1)
		s.gate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.gate:
		return func() { s.gate <- struct{}{} }, nil
	}
}

func (s *CheckpointCustodyStore) ensureKey(ctx context.Context) error {
	return ensureCheckpointCustodyKey(ctx, s)
}

func containsExact(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

func custodyKeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])
}
func custodyReceiptBytes(r custodyReceipt) ([]byte, error) { return json.Marshal(r) }
func custodyArgvDigest(args []string) (string, error) {
	if len(args) == 0 || len(args) > 128 {
		return "", errors.New("controlled argv length is invalid")
	}
	b, err := json.Marshal(args)
	if err != nil || len(b) > 16<<10 {
		return "", errors.New("controlled argv exceeds its identity bound")
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func custodyNewNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func custodyReceiptPath(root, nonce string) string {
	return filepath.Join(root, "receipts", nonce+".json")
}
func custodyErr(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("checkpoint custody %s: %w", op, err)
}
