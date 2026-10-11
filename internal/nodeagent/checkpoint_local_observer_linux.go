//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	checkpointLocalObserverSocketPath  = "/run/vram-governor-local-observer/observer.sock"
	checkpointLocalObserverPolicyPath  = "/etc/vram-governor/checkpoint-local-observer-policy.json"
	checkpointLocalObserverPrivatePath = "/etc/vram-governor/checkpoint-local-observer.key"
	checkpointLocalObserverPublicPath  = "/etc/vram-governor/checkpoint-local-observer.pub"
	checkpointLocalObserverSocketDir   = "/run/vram-governor-local-observer"
	checkpointLocalObserverRequestTTL  = 45 * time.Second
)

// This private configuration is used only by the tagged kernel fixture.
// Public entry points always construct the fixed production values below.
type checkpointLocalObserverRuntimeConfig struct {
	socketPath            string
	socketDir             string
	policyPath            string
	privatePath           string
	publicPath            string
	nodeGroup             string
	trustRoot             string
	fixtureAnchor         bool
	collect               func(context.Context) (CheckpointManagedBinding, error)
	peerDenied            func(uint32, uint32) error
	pinDenied             func() error
	fixturePayloadMutator func(*checkpointLocalObserverPayload) (string, error)
	fixtureMutationResult func(string, bool) error
	fixtureStageSink      func(checkpointLocalObserverStage)
}

type checkpointLocalObserverStage uint8

const (
	checkpointLocalObserverStageNone checkpointLocalObserverStage = iota
	checkpointLocalObserverStageC01
	checkpointLocalObserverStageC02
	checkpointLocalObserverStageC03
	checkpointLocalObserverStageC04
	checkpointLocalObserverStageC05
	checkpointLocalObserverStageC06
	checkpointLocalObserverStageC07
	checkpointLocalObserverStageC08
	checkpointLocalObserverStageC09
	checkpointLocalObserverStageC10
	checkpointLocalObserverStageC11
	checkpointLocalObserverStageC12
	checkpointLocalObserverStageC13
	checkpointLocalObserverStageC14
	checkpointLocalObserverStageC15
	checkpointLocalObserverStageC16
	checkpointLocalObserverStageC17
	checkpointLocalObserverStageC18
	checkpointLocalObserverStageC19
	checkpointLocalObserverStageC20
	checkpointLocalObserverStageC21
	checkpointLocalObserverStageC22
	checkpointLocalObserverStageC23
	checkpointLocalObserverStageC24
	checkpointLocalObserverStageC25
	checkpointLocalObserverStageC26
	checkpointLocalObserverStageC27
	checkpointLocalObserverStageC28
	checkpointLocalObserverStageC29
	checkpointLocalObserverStageC30
	checkpointLocalObserverStageC31
	checkpointLocalObserverStageC32
	checkpointLocalObserverStageC33
	checkpointLocalObserverStageC34
	checkpointLocalObserverStageB01
	checkpointLocalObserverStageB02
	checkpointLocalObserverStageB03
	checkpointLocalObserverStageB04
	checkpointLocalObserverStageB05
	checkpointLocalObserverStageB06
	checkpointLocalObserverStageB07
	checkpointLocalObserverStageB08
	checkpointLocalObserverStageB09
	checkpointLocalObserverStageB10
	checkpointLocalObserverStageB11
	checkpointLocalObserverStageB12
	checkpointLocalObserverStageB13
	checkpointLocalObserverStageB14
	checkpointLocalObserverStageB15
	checkpointLocalObserverStageB16
	checkpointLocalObserverStageB17
	checkpointLocalObserverStageB18
	checkpointLocalObserverStageB19
	checkpointLocalObserverStageB20
	checkpointLocalObserverStageB21
	checkpointLocalObserverStageB22
	checkpointLocalObserverStageB23
	checkpointLocalObserverStageB24
	checkpointLocalObserverStageB25
	checkpointLocalObserverStageB26
	checkpointLocalObserverStageB27
	checkpointLocalObserverStageB28
	checkpointLocalObserverStageB29
	checkpointLocalObserverStageB30
	checkpointLocalObserverStageB31
	checkpointLocalObserverStageB32
	checkpointLocalObserverStageB33
	checkpointLocalObserverStageB34
	checkpointLocalObserverStageB35
	checkpointLocalObserverStageB36
	checkpointLocalObserverStageB37
	checkpointLocalObserverStageB38
)

func checkpointLocalObserverReportStage(config checkpointLocalObserverRuntimeConfig, stage checkpointLocalObserverStage, cause error) error {
	if cause == nil || !config.fixtureAnchor || config.fixtureStageSink == nil || stage == checkpointLocalObserverStageNone {
		return cause
	}
	func() {
		defer func() { _ = recover() }()
		config.fixtureStageSink(stage)
	}()
	return cause
}

func checkpointLocalObserverStageCode(stage checkpointLocalObserverStage) string {
	if stage >= checkpointLocalObserverStageC01 && stage <= checkpointLocalObserverStageC34 {
		return fmt.Sprintf("C%02d", int(stage-checkpointLocalObserverStageC01)+1)
	}
	if stage >= checkpointLocalObserverStageB01 && stage <= checkpointLocalObserverStageB38 {
		return fmt.Sprintf("B%02d", int(stage-checkpointLocalObserverStageB01)+1)
	}
	return "unavailable"
}

func checkpointLocalObserverProductionConfig() checkpointLocalObserverRuntimeConfig {
	return checkpointLocalObserverRuntimeConfig{
		socketPath:  checkpointLocalObserverSocketPath,
		socketDir:   checkpointLocalObserverSocketDir,
		policyPath:  checkpointLocalObserverPolicyPath,
		privatePath: checkpointLocalObserverPrivatePath,
		publicPath:  checkpointLocalObserverPublicPath,
		nodeGroup:   "vram-governor",
		trustRoot:   "/",
	}
}

type checkpointLocalObserverPolicy struct {
	Version          int    `json:"version"`
	PeerUID          uint32 `json:"peer_uid"`
	PeerGID          uint32 `json:"peer_gid"`
	ExecutablePath   string `json:"executable_path"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ControlGroup     string `json:"control_group"`
}

type checkpointLocalObserverFilePin struct {
	path          string
	dev           uint64
	ino           uint64
	uid           uint32
	gid           uint32
	mode          uint32
	size          int64
	sum           [32]byte
	fd            int
	stat          unix.Stat_t
	trustRoot     string
	fixtureAnchor bool
	parents       []checkpointLocalObserverParentPin
}

type checkpointLocalObserverParentPin struct {
	path string
	dev  uint64
	ino  uint64
	uid  uint32
	mode uint32
	fd   int
}

type checkpointLocalObserverPlatformPins struct {
	policy checkpointLocalObserverFilePin
	priv   checkpointLocalObserverFilePin
	pub    checkpointLocalObserverFilePin
}

func runCheckpointLocalObserverPlatform(ctx context.Context) error {
	return checkpointLocalObserverRunWithConfig(ctx, checkpointLocalObserverProductionConfig())
}

func checkpointLocalObserverRunWithConfig(ctx context.Context, config checkpointLocalObserverRuntimeConfig) (returnErr error) {
	if os.Geteuid() != 0 {
		return errors.New("checkpoint local observer broker requires root")
	}
	policy, private, pins, err := checkpointLocalObserverLoadRootMaterial(config)
	if err != nil {
		return err
	}
	defer checkpointLocalObserverClosePins(pins)
	group, err := user.LookupGroup(config.nodeGroup)
	if err != nil {
		return errors.New("fixed node group is unavailable")
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || uint32(groupID) != policy.PeerGID {
		return errors.New("fixed node group differs from the pinned policy")
	}
	if err := checkpointLocalObserverCheckDirectory(config.socketDir, 0, uint32(groupID), 0750, config); err != nil {
		return err
	}
	if _, err := os.Lstat(config.socketPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed checkpoint local observer socket path already exists")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: config.socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("bind fixed checkpoint local observer socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	createdSocket, err := checkpointLocalObserverCaptureSocket(config.socketPath, config)
	if err != nil {
		_ = listener.Close()
		return err
	}
	defer func() {
		_ = listener.Close()
		if checkpointLocalObserverSocketCreatedStillPinned(createdSocket) {
			if err := checkpointLocalObserverUnlinkSocket(createdSocket); err != nil && !errors.Is(err, unix.ENOENT) {
				returnErr = errors.Join(returnErr, err)
			}
		} else {
			returnErr = errors.Join(returnErr, errors.New("observer socket cleanup pin changed; path preserved"))
		}
		checkpointLocalObserverCloseFilePin(createdSocket)
	}()
	if err := os.Chmod(config.socketPath, 0660); err != nil {
		return err
	}
	if err := os.Chown(config.socketPath, 0, int(groupID)); err != nil {
		return err
	}
	socketPin, err := checkpointLocalObserverPinSocket(config)
	if err != nil {
		return err
	}
	defer checkpointLocalObserverCloseFilePin(socketPin)
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		return err
	}

	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	closeDone := make(chan struct{})
	serveCtx, stopServe := context.WithCancel(ctx)
	defer stopServe()
	go func() {
		defer close(closeDone)
		<-serveCtx.Done()
		_ = listener.Close()
	}()
	var terminalAcceptErr error
	for {
		conn, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			if ctx.Err() != nil || errors.Is(acceptErr, net.ErrClosed) {
				break
			}
			terminalAcceptErr = acceptErr
			stopServe()
			break
		}
		select {
		case sem <- struct{}{}:
			wg.Add(1)
			go func(conn *net.UnixConn) {
				defer wg.Done()
				defer func() { <-sem }()
				defer conn.Close()
				requestCtx, cancel := context.WithTimeout(serveCtx, checkpointLocalObserverRequestTTL)
				defer cancel()
				_ = checkpointLocalObserverServeConn(requestCtx, conn, policy, private, pins, socketPin, config)
			}(conn)
		default:
			_ = conn.Close()
		}
	}
	stopServe()
	wg.Wait()
	<-closeDone
	if terminalAcceptErr != nil {
		return terminalAcceptErr
	}
	return nil
}

func observeCheckpointLocalObserverPlatform(ctx context.Context) (CheckpointLocalObserverResult, error) {
	return checkpointLocalObserverObserveWithConfig(ctx, checkpointLocalObserverProductionConfig())
}

func checkpointLocalObserverObserveWithConfig(ctx context.Context, config checkpointLocalObserverRuntimeConfig) (result CheckpointLocalObserverResult, resultErr error) {
	stage := checkpointLocalObserverStageNone
	defer func() { resultErr = checkpointLocalObserverReportStage(config, stage, resultErr) }()
	var zero CheckpointLocalObserverResult
	if os.Geteuid() == 0 {
		stage = checkpointLocalObserverStageC01
		return zero, errors.New("fixed checkpoint local observer client is the unprivileged node path")
	}
	public, pubPin, err := checkpointLocalObserverReadPublicKey(config)
	if err != nil {
		stage = checkpointLocalObserverStageC02
		return zero, err
	}
	defer checkpointLocalObserverCloseFilePin(pubPin)
	socketPin, err := checkpointLocalObserverPinSocket(config)
	if err != nil {
		stage = checkpointLocalObserverStageC03
		return zero, err
	}
	defer checkpointLocalObserverCloseFilePin(socketPin)
	self, err := checkpointLocalObserverOpenCurrent(os.Getpid())
	if err != nil {
		stage = checkpointLocalObserverStageC04
		return zero, err
	}
	defer self.close()
	if self.uid == 0 {
		stage = checkpointLocalObserverStageC05
		return zero, errors.New("checkpoint local observer client peer is root")
	}
	var nonceRaw [checkpointLocalObserverNonceBytes]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		stage = checkpointLocalObserverStageC06
		return zero, err
	}
	nonce := hex.EncodeToString(nonceRaw[:])
	request, err := checkpointLocalObserverCanonicalRequest(nonce)
	if err != nil {
		stage = checkpointLocalObserverStageC07
		return zero, err
	}
	address := &net.UnixAddr{Name: config.socketPath, Net: "unix"}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	connRaw, err := dialer.DialContext(ctx, "unix", address.String())
	if err != nil {
		stage = checkpointLocalObserverStageC08
		return zero, err
	}
	conn := connRaw.(*net.UnixConn)
	defer conn.Close()
	deadline := time.Now().Add(checkpointLocalObserverRequestTTL)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		stage = checkpointLocalObserverStageC09
		return zero, err
	}
	watchDone := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer func() { close(watchDone); <-watchExited }()
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		stage = checkpointLocalObserverStageC10
		return zero, err
	}
	peerUID, peerGID, peerPID, err := checkpointLocalObserverPeer(conn)
	if err != nil || peerUID != 0 || peerGID != checkpointLocalObserverExpectedGroup(config.nodeGroup) || peerPID <= 1 {
		stage = checkpointLocalObserverStageC11
		return zero, errors.New("checkpoint local observer socket peer is not a root broker")
	}
	broker, err := checkpointLocalObserverOpenCrossUID(peerPID)
	if err != nil {
		stage = checkpointLocalObserverStageC12
		return zero, errors.New("checkpoint local observer root peer identity is unavailable")
	}
	defer broker.close()
	if broker.uid != 0 {
		stage = checkpointLocalObserverStageC13
		return zero, errors.New("checkpoint local observer root peer is not privileged")
	}
	if err := checkpointLocalObserverWriteFull(conn, request); err != nil {
		stage = checkpointLocalObserverStageC14
		return zero, err
	}
	if err := conn.CloseWrite(); err != nil {
		stage = checkpointLocalObserverStageC15
		return zero, err
	}
	wire, err := io.ReadAll(io.LimitReader(conn, checkpointLocalObserverMaxFrame+1))
	if err != nil || len(wire) > checkpointLocalObserverMaxFrame {
		stage = checkpointLocalObserverStageC16
		return zero, errors.New("checkpoint local observer response is unreadable or oversized")
	}
	if err := checkpointLocalObserverCheckFilePin(pubPin); err != nil {
		stage = checkpointLocalObserverStageC17
		return zero, err
	}
	result, err = checkpointLocalObserverVerify(wire, public, nonce, time.Now().UTC())
	if err != nil {
		stage = checkpointLocalObserverStageC18
		return zero, err
	}
	selfGID, gidErr := checkpointLocalObserverProcessGID(self.pid)
	if gidErr != nil || result.Caller.PID != self.pid || result.Caller.UID != self.uid || result.Caller.GID != selfGID || result.Caller.StartTicks != self.start || result.Caller.PIDNamespaceInode != self.namespace.Inode || result.Caller.ExecutablePath != self.exe || !strings.EqualFold(result.Caller.ExecutableSHA256, self.exeSHA256) || result.Caller.ControlGroup != self.cgroup {
		stage = checkpointLocalObserverStageC19
		return zero, errors.New("signed checkpoint local observer caller differs from this held client")
	}
	worker, err := checkpointLocalObserverOpenCrossUID(result.Worker.PID)
	if err != nil {
		stage = checkpointLocalObserverStageC20
		return zero, err
	}
	defer worker.close()
	if worker.start != result.Worker.StartTicks || worker.uid != 0 || result.Worker.PIDNamespaceInode != self.namespace.Inode {
		stage = checkpointLocalObserverStageC21
		return zero, errors.New("signed worker does not match public start and held cross-UID pidfd")
	}
	workerAgain, err := checkpointLocalObserverOpenCrossUID(result.Worker.PID)
	if err != nil {
		stage = checkpointLocalObserverStageC22
		return zero, err
	}
	defer workerAgain.close()
	if workerAgain.start != worker.start || workerAgain.uid != worker.uid || workerAgain.pid != worker.pid {
		stage = checkpointLocalObserverStageC23
		return zero, errors.New("signed worker public start identity changed during observer IPC")
	}
	brokerAgain, err := checkpointLocalObserverOpenCrossUID(peerPID)
	if err != nil {
		stage = checkpointLocalObserverStageC24
		return zero, err
	}
	defer brokerAgain.close()
	if brokerAgain.uid != broker.uid || brokerAgain.start != broker.start || brokerAgain.pid != broker.pid {
		stage = checkpointLocalObserverStageC25
		return zero, errors.New("root broker public start identity changed during observer IPC")
	}
	selfAgain, err := checkpointLocalObserverOpenCurrent(self.pid)
	if err != nil {
		stage = checkpointLocalObserverStageC26
		return zero, err
	}
	defer selfAgain.close()
	selfAgainIdentity, err := checkpointLocalObserverIdentityOf(selfAgain)
	if err != nil || !checkpointLocalObserverIdentityMatches(result.Caller, selfAgainIdentity) {
		stage = checkpointLocalObserverStageC27
		return zero, errors.New("caller identity changed during observer IPC")
	}
	if err := checkpointLocalPIDFDAlive(self.pidfd); err != nil {
		stage = checkpointLocalObserverStageC28
		return zero, err
	}
	if err := checkpointLocalPIDFDAlive(broker.pidfd); err != nil {
		stage = checkpointLocalObserverStageC29
		return zero, err
	}
	if err := checkpointLocalPIDFDAlive(worker.pidfd); err != nil {
		stage = checkpointLocalObserverStageC30
		return zero, err
	}
	if err := checkpointLocalPIDFDAlive(workerAgain.pidfd); err != nil {
		stage = checkpointLocalObserverStageC31
		return zero, err
	}
	if err := checkpointLocalPIDFDAlive(brokerAgain.pidfd); err != nil {
		stage = checkpointLocalObserverStageC32
		return zero, err
	}
	if err := checkpointLocalObserverCheckFilePin(pubPin); err != nil {
		stage = checkpointLocalObserverStageC33
		return zero, err
	}
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		stage = checkpointLocalObserverStageC34
		return zero, err
	}
	return result, nil
}

func checkpointLocalObserverServeConn(ctx context.Context, conn *net.UnixConn, policy checkpointLocalObserverPolicy, private ed25519.PrivateKey, pins checkpointLocalObserverPlatformPins, socketPin checkpointLocalObserverFilePin, config checkpointLocalObserverRuntimeConfig) (resultErr error) {
	stage := checkpointLocalObserverStageNone
	defer func() { resultErr = checkpointLocalObserverReportStage(config, stage, resultErr) }()
	deadline := time.Now().Add(checkpointLocalObserverRequestTTL)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		stage = checkpointLocalObserverStageB01
		return err
	}
	watchDone := make(chan struct{})
	watchExited := make(chan struct{})
	go func() {
		defer close(watchExited)
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer func() { close(watchDone); <-watchExited }()
	peerUID, peerGID, peerPID, err := checkpointLocalObserverPeer(conn)
	if err != nil || !checkpointLocalObserverPeerMatches(peerUID, peerGID, policy) || peerPID <= 1 {
		if config.peerDenied != nil {
			if markerErr := config.peerDenied(peerUID, peerGID); markerErr != nil {
				stage = checkpointLocalObserverStageB02
				return errors.Join(errors.New("checkpoint local observer peer credentials are not allowlisted"), markerErr)
			}
		}
		stage = checkpointLocalObserverStageB03
		return errors.New("checkpoint local observer peer credentials are not allowlisted")
	}
	peer, err := checkpointLocalObserverOpenCurrent(peerPID)
	if err != nil {
		stage = checkpointLocalObserverStageB04
		return err
	}
	defer peer.close()
	processGID, gidErr := checkpointLocalObserverProcessGID(peerPID)
	if gidErr != nil || peer.uid != peerUID || processGID != peerGID || !checkpointLocalObserverPeerMatches(peer.uid, peerGID, policy) || peer.exe != policy.ExecutablePath || !strings.EqualFold(peer.exeSHA256, policy.ExecutableSHA256) || peer.cgroup != policy.ControlGroup {
		stage = checkpointLocalObserverStageB05
		return errors.New("checkpoint local observer peer identity differs from fixed root policy")
	}
	var input []byte
	input, err = io.ReadAll(io.LimitReader(conn, checkpointLocalObserverMaxFrame+1))
	if err != nil || len(input) > checkpointLocalObserverMaxFrame {
		stage = checkpointLocalObserverStageB06
		return errors.New("checkpoint local observer request is unreadable or oversized")
	}
	request, err := checkpointLocalObserverDecodeRequest(input)
	if err != nil {
		stage = checkpointLocalObserverStageB07
		return err
	}
	if err := checkpointLocalObserverRecheckPins(pins, private); err != nil {
		stage = checkpointLocalObserverStageB08
		return checkpointLocalObserverReportPinDenial(err, config)
	}
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		stage = checkpointLocalObserverStageB09
		return err
	}
	for _, held := range []*checkpointHeldLocalProcess{peer} {
		if err := checkpointLocalPIDFDAlive(held.pidfd); err != nil {
			stage = checkpointLocalObserverStageB10
			return err
		}
	}
	caller, err := checkpointLocalObserverIdentityOf(peer)
	if err != nil {
		stage = checkpointLocalObserverStageB11
		return err
	}
	initProcess, err := checkpointLocalObserverOpenCurrent(1)
	if err != nil {
		stage = checkpointLocalObserverStageB12
		return err
	}
	defer initProcess.close()
	if initProcess.uid != 0 || initProcess.namespace != peer.namespace {
		stage = checkpointLocalObserverStageB13
		return errors.New("checkpoint local observer namespace init is not the local root init")
	}
	initIdentity, err := checkpointLocalObserverIdentityOf(initProcess)
	if err != nil {
		stage = checkpointLocalObserverStageB14
		return err
	}
	first, err := checkpointLocalObserverCollectWithConfig(ctx, config)
	if err != nil {
		stage = checkpointLocalObserverStageB15
		return err
	}
	worker1, err := checkpointLocalObserverOpenCurrent(first.Association.Identity.PID)
	if err != nil {
		stage = checkpointLocalObserverStageB16
		return err
	}
	defer worker1.close()
	if worker1.uid != 0 || worker1.namespace != peer.namespace || worker1.start != first.Association.Identity.ProcessStartTicks || worker1.cgroup != first.Association.ControlGroup {
		stage = checkpointLocalObserverStageB17
		return errors.New("fixed managed worker is not root-owned in caller namespace and cgroup")
	}
	workerIdentity, err := checkpointLocalObserverIdentityOf(worker1)
	if err != nil {
		stage = checkpointLocalObserverStageB18
		return err
	}
	second, err := checkpointLocalObserverCollectWithConfig(ctx, config)
	if err != nil || !checkpointLocalObserverBindingStable(first, second) {
		stage = checkpointLocalObserverStageB19
		return errors.New("fixed managed association changed across the two fresh observations")
	}
	worker2, err := checkpointLocalObserverOpenCurrent(second.Association.Identity.PID)
	if err != nil {
		stage = checkpointLocalObserverStageB20
		return err
	}
	defer worker2.close()
	worker2Identity, err := checkpointLocalObserverIdentityOf(worker2)
	if err != nil || worker2.start != worker1.start || worker2.namespace != worker1.namespace || worker2.uid != worker1.uid || !checkpointLocalObserverIdentityMatches(workerIdentity, worker2Identity) {
		stage = checkpointLocalObserverStageB21
		return errors.New("fixed managed worker changed during observation")
	}
	if err := checkpointLocalObserverRecheckPins(pins, private); err != nil {
		stage = checkpointLocalObserverStageB22
		return checkpointLocalObserverReportPinDenial(err, config)
	}
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		stage = checkpointLocalObserverStageB23
		return err
	}
	for _, held := range []*checkpointHeldLocalProcess{peer, initProcess, worker1, worker2} {
		if err := checkpointLocalPIDFDAlive(held.pidfd); err != nil {
			stage = checkpointLocalObserverStageB24
			return err
		}
	}
	peerAgain, err := checkpointLocalObserverOpenCurrent(peerPID)
	if err != nil {
		stage = checkpointLocalObserverStageB25
		return err
	}
	defer peerAgain.close()
	initAgain, err := checkpointLocalObserverOpenCurrent(1)
	if err != nil {
		stage = checkpointLocalObserverStageB26
		return err
	}
	defer initAgain.close()
	workerAgain, err := checkpointLocalObserverOpenCurrent(worker1.pid)
	if err != nil {
		stage = checkpointLocalObserverStageB27
		return err
	}
	defer workerAgain.close()
	peerIdentity, err := checkpointLocalObserverIdentityOf(peerAgain)
	if err != nil {
		stage = checkpointLocalObserverStageB28
		return err
	}
	initCurrent, err := checkpointLocalObserverIdentityOf(initAgain)
	if err != nil {
		stage = checkpointLocalObserverStageB29
		return err
	}
	workerCurrent, err := checkpointLocalObserverIdentityOf(workerAgain)
	if err != nil {
		stage = checkpointLocalObserverStageB30
		return err
	}
	if !checkpointLocalObserverIdentityMatches(caller, peerIdentity) || !checkpointLocalObserverIdentityMatches(initIdentity, initCurrent) || !checkpointLocalObserverIdentityMatches(workerIdentity, workerCurrent) {
		stage = checkpointLocalObserverStageB31
		return errors.New("caller, namespace init, or managed worker identity drifted before response")
	}
	now := time.Now().UTC()
	payload := checkpointLocalObserverPayload{
		Version: checkpointLocalObserverVersion, Nonce: request.Nonce,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(checkpointLocalObserverMaxLifetime).Format(time.RFC3339Nano),
		Caller: caller, Init: initIdentity, Worker: workerIdentity, Binding: second,
	}
	mutation := ""
	if config.fixtureAnchor && config.fixturePayloadMutator != nil {
		mutation, err = config.fixturePayloadMutator(&payload)
		if err != nil {
			stage = checkpointLocalObserverStageB32
			return err
		}
	}
	wire, err := checkpointLocalObserverSign(payload, private)
	if mutation != "" && config.fixtureMutationResult != nil {
		if markerErr := config.fixtureMutationResult(mutation, err == nil); markerErr != nil {
			stage = checkpointLocalObserverStageB33
			return errors.Join(err, markerErr)
		}
	}
	if err != nil {
		stage = checkpointLocalObserverStageB34
		return err
	}
	if err := checkpointLocalObserverRecheckPins(pins, private); err != nil {
		stage = checkpointLocalObserverStageB35
		return checkpointLocalObserverReportPinDenial(err, config)
	}
	if err := checkpointLocalObserverCheckSocketPin(socketPin); err != nil {
		stage = checkpointLocalObserverStageB36
		return err
	}
	for _, held := range []*checkpointHeldLocalProcess{peer, initProcess, worker1, worker2, peerAgain, initAgain, workerAgain} {
		if err := checkpointLocalPIDFDAlive(held.pidfd); err != nil {
			stage = checkpointLocalObserverStageB37
			return err
		}
	}
	stage = checkpointLocalObserverStageB38
	return checkpointLocalObserverWriteFull(conn, wire)
}

func checkpointLocalObserverReportPinDenial(cause error, config checkpointLocalObserverRuntimeConfig) error {
	if config.pinDenied == nil {
		return cause
	}
	return errors.Join(cause, config.pinDenied())
}

func checkpointLocalObserverPeerMatches(uid, gid uint32, policy checkpointLocalObserverPolicy) bool {
	return uid == policy.PeerUID && gid == policy.PeerGID
}

func checkpointLocalObserverIdentityMatches(expected, current CheckpointLocalObserverIdentity) bool {
	return expected == current
}

func checkpointLocalObserverBindingStable(first, second CheckpointManagedBinding) bool {
	return first.Version == second.Version && first.CurrentIncarnation == second.CurrentIncarnation && first.PlanSHA256 == second.PlanSHA256 && first.CustodyBindingSHA256 == second.CustodyBindingSHA256 && first.Alias == second.Alias && first.Association == second.Association && first.Placement.Backend == second.Placement.Backend && first.Placement.PhysicalIdentity == second.Placement.PhysicalIdentity && first.Placement.ChildMaskUUID == second.Placement.ChildMaskUUID && first.Placement.RuntimeDeviceToken == second.Placement.RuntimeDeviceToken && first.Placement.RuntimeVersion == second.Placement.RuntimeVersion
}

func checkpointLocalObserverWriteFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return errors.New("observer writer reported an invalid byte count")
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func checkpointLocalObserverCollect(ctx context.Context) (CheckpointManagedBinding, error) {
	if os.Geteuid() != 0 {
		return CheckpointManagedBinding{}, errors.New("root managed collector is unavailable")
	}
	return observeCheckpointManagedBindingLinux(ctx, checkpointManagedObservationSource{
		openPlan: func(callCtx context.Context) (*PinnedCheckpointLaunchPlan, error) {
			return OpenCheckpointLaunchPlan(callCtx, checkpointFixedPlanPath)
		},
		openStore: openCheckpointCustodyStoreReadOnly,
		associate: func(callCtx context.Context, store *CheckpointCustodyStore, plan CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
			endpoint := managedCheckpointEndpoint(plan)
			verified, ok, err := store.VerifyBinding(callCtx, endpoint, checkpointIdentityServiceUnit)
			if err != nil || !ok {
				if err == nil {
					err = errors.New("authenticated staged receipt is absent")
				}
				return CheckpointVerifiedUnitAssociation{}, err
			}
			if err := validateManagedCheckpointReceipt(verified, plan, endpoint); err != nil {
				return CheckpointVerifiedUnitAssociation{}, err
			}
			request := CheckpointUnitIdentityRequest{
				Custody:       store,
				Identity:      CheckpointIdentityRequest{Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, ModelPath: verified.ArtifactPath, ExpectedModelSHA256: plan.Model.SHA256, ApprovedModelRoots: []string{filepath.Dir(verified.ArtifactPath)}, ExpectedExecutableSHA256: plan.Executable.SHA256},
				ExpectedAlias: plan.Alias,
			}
			return ObserveCheckpointManagedUnit(callCtx, request)
		},
		alias: observeCheckpointManagedAlias,
		placement: func(callCtx context.Context, plan CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
			return refreshCheckpointDevicePlacementPlatform(callCtx, plan)
		},
		// Keep the existing nested host attribution route. Local /proc GPU PID
		// inventories cannot join host physical processes across PID namespaces.
		namespaceRoute:  checkpointWorkerUsesNestedPIDNamespace,
		nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver,
		footprint:       observeManagedCheckpointFootprint,
		readArgv:        readManagedCheckpointArgv,
	})
}

func checkpointLocalObserverCollectWithConfig(ctx context.Context, config checkpointLocalObserverRuntimeConfig) (CheckpointManagedBinding, error) {
	if config.collect != nil {
		return config.collect(ctx)
	}
	return checkpointLocalObserverCollect(ctx)
}

func checkpointLocalObserverLoadRootMaterial(config checkpointLocalObserverRuntimeConfig) (checkpointLocalObserverPolicy, ed25519.PrivateKey, checkpointLocalObserverPlatformPins, error) {
	var empty checkpointLocalObserverPlatformPins
	policyBytes, policyPin, err := checkpointLocalObserverReadRootFile(config.policyPath, 0600, checkpointLocalObserverMaxFrame, config)
	if err != nil {
		return checkpointLocalObserverPolicy{}, nil, empty, err
	}
	policy, err := checkpointLocalObserverDecodePolicy(policyBytes)
	if err != nil {
		checkpointLocalObserverCloseFilePin(policyPin)
		return checkpointLocalObserverPolicy{}, nil, empty, err
	}
	if policy.Version != checkpointLocalObserverVersion || policy.PeerUID == 0 || policy.PeerGID == 0 || !checkpointLocalObserverHex64.MatchString(policy.ExecutableSHA256) || !filepath.IsAbs(policy.ExecutablePath) || filepath.Clean(policy.ExecutablePath) != policy.ExecutablePath || !strings.HasPrefix(policy.ControlGroup, "/") || filepath.Clean(policy.ControlGroup) != policy.ControlGroup {
		checkpointLocalObserverCloseFilePin(policyPin)
		return checkpointLocalObserverPolicy{}, nil, empty, errors.New("fixed root policy is malformed or noncanonical")
	}
	privateBytes, privatePin, err := checkpointLocalObserverReadRootFile(config.privatePath, 0600, ed25519.PrivateKeySize, config)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		checkpointLocalObserverCloseFilePin(policyPin)
		checkpointLocalObserverCloseFilePin(privatePin)
		return checkpointLocalObserverPolicy{}, nil, empty, errors.New("fixed root signing key is unavailable or invalid")
	}
	publicBytes, publicPin, err := checkpointLocalObserverReadRootFile(config.publicPath, 0640, ed25519.PublicKeySize, config)
	if err != nil || len(publicBytes) != ed25519.PublicKeySize || publicPin.gid != policy.PeerGID || !bytes.Equal(publicBytes, ed25519.PrivateKey(privateBytes).Public().(ed25519.PublicKey)) {
		checkpointLocalObserverCloseFilePin(policyPin)
		checkpointLocalObserverCloseFilePin(privatePin)
		checkpointLocalObserverCloseFilePin(publicPin)
		return checkpointLocalObserverPolicy{}, nil, empty, errors.New("fixed public key does not match the separate root signing key")
	}
	pins := checkpointLocalObserverPlatformPins{policy: policyPin, priv: privatePin, pub: publicPin}
	return policy, ed25519.PrivateKey(privateBytes), pins, nil
}

func checkpointLocalObserverReadPublicKey(config checkpointLocalObserverRuntimeConfig) (ed25519.PublicKey, checkpointLocalObserverFilePin, error) {
	group, err := user.LookupGroup(config.nodeGroup)
	if err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupID == 0 {
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed node key group is invalid")
	}
	raw, pin, err := checkpointLocalObserverReadRootFile(config.publicPath, 0640, ed25519.PublicKeySize, config)
	if err != nil || pin.gid != uint32(groupID) || len(raw) != ed25519.PublicKeySize {
		checkpointLocalObserverCloseFilePin(pin)
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed root public key is not readable by the pinned node group")
	}
	return ed25519.PublicKey(raw), pin, nil
}

func checkpointLocalObserverReadRootFile(path string, mode uint32, max int64, config checkpointLocalObserverRuntimeConfig) ([]byte, checkpointLocalObserverFilePin, error) {
	parents, err := checkpointLocalObserverOpenParents(path, config.trustRoot, config.fixtureAnchor)
	if err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			checkpointLocalObserverCloseParents(parents)
		}
	}()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	pin := checkpointLocalObserverFilePin{path: path, fd: fd, parents: parents, trustRoot: config.trustRoot, fixtureAnchor: config.fixtureAnchor}
	fileOpen := true
	defer func() {
		if closeOnError && fileOpen {
			_ = unix.Close(fd)
		}
	}()
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != 0 || before.Nlink != 1 || before.Mode&07777 != mode || before.Size <= 0 || before.Size > max {
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed root file owner, mode, type, link count, or size is unsafe")
	}
	raw, err := checkpointLocalObserverReadFD(fd, max)
	if err != nil || int64(len(raw)) != before.Size || int64(len(raw)) > max {
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed root file content is truncated or oversized")
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil || !checkpointLocalObserverSameStat(&before, &after) {
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed root file changed while being read")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathInfo.Mode()&os.ModeSymlink != 0 || uint64(pathStat.Dev) != uint64(before.Dev) || pathStat.Ino != before.Ino {
		return nil, checkpointLocalObserverFilePin{}, errors.New("fixed root file path no longer names the opened inode")
	}
	pin.dev, pin.ino, pin.uid, pin.gid, pin.mode, pin.size, pin.sum, pin.stat = uint64(before.Dev), before.Ino, before.Uid, before.Gid, before.Mode&07777, before.Size, sha256.Sum256(raw), before
	if err := checkpointLocalObserverCheckParentPins(pin.parents); err != nil {
		return nil, checkpointLocalObserverFilePin{}, err
	}
	closeOnError, fileOpen = false, false
	return raw, pin, nil
}

func checkpointLocalObserverReadFD(fd int, max int64) ([]byte, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Size < 0 || st.Size > max {
		return nil, errors.New("fixed root file size is outside its bound")
	}
	raw := make([]byte, st.Size)
	read := 0
	for read < len(raw) {
		n, err := unix.Pread(fd, raw[read:], int64(read))
		if err != nil || n == 0 {
			return nil, errors.New("fixed root file is truncated or unreadable")
		}
		read += n
	}
	return raw, nil
}

func checkpointLocalObserverOpenParents(path, trustRoot string, fixtureAnchor bool) ([]checkpointLocalObserverParentPin, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !filepath.IsAbs(trustRoot) || filepath.Clean(trustRoot) != trustRoot {
		return nil, errors.New("fixed protected path is not canonical")
	}
	if trustRoot != "/" && !fixtureAnchor {
		return nil, errors.New("non-production trust anchors are permitted only in the private fixture")
	}
	relative, err := filepath.Rel(trustRoot, filepath.Dir(path))
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("protected path escapes its pinned trust root")
	}
	rootFD, err := checkpointLocalObserverOpenAbsoluteDirectory(trustRoot, trustRoot == "/")
	if err != nil {
		return nil, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(rootFD, &rootStat); err != nil {
		_ = unix.Close(rootFD)
		return nil, err
	}
	if rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Uid != 0 || rootStat.Mode&0022 != 0 {
		_ = unix.Close(rootFD)
		return nil, errors.New("trusted root anchor is not root-owned and non-writable")
	}
	current := trustRoot
	parents := []checkpointLocalObserverParentPin{{path: trustRoot, dev: uint64(rootStat.Dev), ino: rootStat.Ino, uid: rootStat.Uid, mode: rootStat.Mode & 07777, fd: rootFD}}
	failed := func(err error) ([]checkpointLocalObserverParentPin, error) {
		checkpointLocalObserverCloseParents(parents)
		return nil, err
	}
	parentFD := rootFD
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" {
			continue
		}
		if component == "." {
			continue
		}
		nextFD, err := unix.Openat(parentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return failed(err)
		}
		current = filepath.Join(current, component)
		var st unix.Stat_t
		if err := unix.Fstat(nextFD, &st); err != nil {
			_ = unix.Close(nextFD)
			return failed(err)
		}
		var pathStat unix.Stat_t
		if err := unix.Lstat(current, &pathStat); err != nil {
			_ = unix.Close(nextFD)
			return failed(err)
		}
		if st.Dev != pathStat.Dev || st.Ino != pathStat.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0022 != 0 {
			_ = unix.Close(nextFD)
			return failed(fmt.Errorf("protected parent %q is substituted, untrusted, or writable", current))
		}
		parents = append(parents, checkpointLocalObserverParentPin{path: current, dev: uint64(st.Dev), ino: st.Ino, uid: st.Uid, mode: st.Mode & 07777, fd: nextFD})
		parentFD = nextFD
	}
	return parents, nil
}

func checkpointLocalObserverOpenAbsoluteDirectory(path string, strict bool) (int, error) {
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	current := "/"
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(fd, component, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Close(fd)
			return -1, err
		}
		current = filepath.Join(current, component)
		var held, named unix.Stat_t
		if unix.Fstat(next, &held) != nil || unix.Lstat(current, &named) != nil || held.Dev != named.Dev || held.Ino != named.Ino || held.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			_ = unix.Close(fd)
			return -1, errors.New("trust root path is substituted or not a directory")
		}
		if strict && (held.Uid != 0 || held.Mode&0022 != 0) {
			_ = unix.Close(next)
			_ = unix.Close(fd)
			return -1, errors.New("production trust ancestry is not root-owned and non-writable")
		}
		_ = unix.Close(fd)
		fd = next
	}
	return fd, nil
}

func checkpointLocalObserverCheckFilePin(pin checkpointLocalObserverFilePin) error {
	if pin.fd < 0 || checkpointLocalObserverCheckParentPins(pin.parents) != nil {
		return errors.New("fixed root file parent descriptor changed")
	}
	var st unix.Stat_t
	if unix.Fstat(pin.fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Dev) != pin.dev || st.Ino != pin.ino || st.Uid != pin.uid || st.Gid != pin.gid || st.Nlink != 1 || st.Mode&07777 != pin.mode || st.Size != pin.size || !checkpointLocalObserverSameStat(&pin.stat, &st) {
		return errors.New("fixed root file pin changed")
	}
	raw := make([]byte, pin.size)
	read := 0
	for read < len(raw) {
		n, err := unix.Pread(pin.fd, raw[read:], int64(read))
		if err != nil || n == 0 {
			return errors.New("held fixed root file content is unreadable")
		}
		read += n
	}
	if sha256.Sum256(raw) != pin.sum {
		return errors.New("held fixed root file bytes changed")
	}
	pathInfo, err := os.Lstat(pin.path)
	if err != nil {
		return err
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathInfo.Mode()&os.ModeSymlink != 0 || uint64(pathStat.Dev) != pin.dev || pathStat.Ino != pin.ino {
		return errors.New("fixed root file pathname was substituted")
	}
	return nil
}

func checkpointLocalObserverCloseParents(parents []checkpointLocalObserverParentPin) {
	for index := len(parents) - 1; index >= 0; index-- {
		if parents[index].fd >= 0 {
			_ = unix.Close(parents[index].fd)
		}
	}
}

func checkpointLocalObserverCloseFilePin(pin checkpointLocalObserverFilePin) {
	if pin.path != "" && pin.fd >= 0 {
		_ = unix.Close(pin.fd)
	}
	checkpointLocalObserverCloseParents(pin.parents)
}

func checkpointLocalObserverClosePins(pins checkpointLocalObserverPlatformPins) {
	checkpointLocalObserverCloseFilePin(pins.policy)
	checkpointLocalObserverCloseFilePin(pins.priv)
	checkpointLocalObserverCloseFilePin(pins.pub)
}

func checkpointLocalObserverCheckParentPins(parents []checkpointLocalObserverParentPin) error {
	if len(parents) == 0 || parents[0].uid != 0 || parents[0].mode&0022 != 0 {
		return errors.New("protected path parent pins are absent")
	}
	for _, pin := range parents {
		var held, named unix.Stat_t
		if pin.fd < 0 || unix.Fstat(pin.fd, &held) != nil || unix.Lstat(pin.path, &named) != nil || held.Mode&unix.S_IFMT != unix.S_IFDIR || named.Mode&unix.S_IFMT != unix.S_IFDIR || uint64(held.Dev) != pin.dev || held.Ino != pin.ino || uint64(named.Dev) != pin.dev || named.Ino != pin.ino || held.Uid != pin.uid || named.Uid != pin.uid || held.Mode&07777 != pin.mode || named.Mode&07777 != pin.mode || held.Mode&0022 != 0 || named.Mode&0022 != 0 {
			return errors.New("protected parent descriptor or pathname changed")
		}
	}
	return nil
}

func checkpointLocalObserverRecheckPins(pins checkpointLocalObserverPlatformPins, private ed25519.PrivateKey) error {
	if err := checkpointLocalObserverCheckFilePin(pins.policy); err != nil {
		return err
	}
	if err := checkpointLocalObserverCheckFilePin(pins.priv); err != nil {
		return err
	}
	if err := checkpointLocalObserverCheckFilePin(pins.pub); err != nil {
		return err
	}
	if len(private) != ed25519.PrivateKeySize {
		return errors.New("root private key is no longer available")
	}
	return nil
}

func checkpointLocalObserverDecodePolicy(raw []byte) (checkpointLocalObserverPolicy, error) {
	var policy checkpointLocalObserverPolicy
	if len(raw) == 0 || len(raw) > checkpointLocalObserverMaxFrame || checkpointLocalObserverRejectDuplicateKeys(raw) != nil {
		return policy, errors.New("fixed root policy is empty, oversized, or duplicated")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return checkpointLocalObserverPolicy{}, errors.New("fixed root policy fields are invalid")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return checkpointLocalObserverPolicy{}, errors.New("fixed root policy has trailing data")
	}
	canonical, err := json.Marshal(policy)
	if err != nil || !bytes.Equal(raw, canonical) {
		return checkpointLocalObserverPolicy{}, errors.New("fixed root policy is not canonical typed JSON")
	}
	return policy, nil
}

func checkpointLocalObserverCheckDirectory(path string, uid, gid, mode uint32, config checkpointLocalObserverRuntimeConfig) error {
	parents, err := checkpointLocalObserverOpenParents(filepath.Join(path, "marker"), config.trustRoot, config.fixtureAnchor)
	if err != nil {
		return err
	}
	defer checkpointLocalObserverCloseParents(parents)
	if err := checkpointLocalObserverCheckParentPins(parents); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	last := parents[len(parents)-1]
	var held unix.Stat_t
	if unix.Fstat(last.fd, &held) != nil || st.Dev != held.Dev || st.Ino != held.Ino || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uid || st.Gid != gid || st.Mode&07777 != mode || held.Uid != uid || held.Gid != gid || held.Mode&07777 != mode {
		return errors.New("fixed runtime directory ownership or mode is unsafe")
	}
	return nil
}

func checkpointLocalObserverPinSocket(config checkpointLocalObserverRuntimeConfig) (checkpointLocalObserverFilePin, error) {
	if err := checkpointLocalObserverCheckDirectory(config.socketDir, 0, checkpointLocalObserverExpectedGroup(config.nodeGroup), 0750, config); err != nil {
		return checkpointLocalObserverFilePin{}, err
	}
	parents, err := checkpointLocalObserverOpenParents(config.socketPath, config.trustRoot, config.fixtureAnchor)
	if err != nil {
		return checkpointLocalObserverFilePin{}, err
	}
	var st unix.Stat_t
	if err := unix.Lstat(config.socketPath, &st); err != nil {
		checkpointLocalObserverCloseParents(parents)
		return checkpointLocalObserverFilePin{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Uid != 0 || st.Gid != checkpointLocalObserverExpectedGroup(config.nodeGroup) || st.Mode&0777 != 0660 || st.Nlink != 1 {
		checkpointLocalObserverCloseParents(parents)
		return checkpointLocalObserverFilePin{}, errors.New("fixed observer socket identity is unsafe")
	}
	return checkpointLocalObserverFilePin{path: config.socketPath, dev: uint64(st.Dev), ino: st.Ino, uid: st.Uid, gid: st.Gid, mode: st.Mode & 07777, fd: -1, parents: parents, trustRoot: config.trustRoot, fixtureAnchor: config.fixtureAnchor}, nil
}

func checkpointLocalObserverExpectedGroup(groupName string) uint32 {
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return ^uint32(0)
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return ^uint32(0)
	}
	return uint32(gid)
}

func checkpointLocalObserverCheckSocketPin(pin checkpointLocalObserverFilePin) error {
	if checkpointLocalObserverCheckParentPins(pin.parents) != nil || !checkpointLocalObserverSocketStillPinned(pin) {
		return errors.New("fixed observer socket path changed")
	}
	return nil
}

func checkpointLocalObserverSocketStillPinned(pin checkpointLocalObserverFilePin) bool {
	var st unix.Stat_t
	err := unix.Lstat(pin.path, &st)
	return err == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK && uint64(st.Dev) == pin.dev && st.Ino == pin.ino && st.Uid == pin.uid && st.Gid == pin.gid && st.Mode&07777 == pin.mode && st.Nlink == 1
}

func checkpointLocalObserverCaptureSocket(path string, config checkpointLocalObserverRuntimeConfig) (checkpointLocalObserverFilePin, error) {
	parents, err := checkpointLocalObserverOpenParents(path, config.trustRoot, config.fixtureAnchor)
	if err != nil {
		return checkpointLocalObserverFilePin{}, err
	}
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		checkpointLocalObserverCloseParents(parents)
		return checkpointLocalObserverFilePin{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Nlink != 1 {
		checkpointLocalObserverCloseParents(parents)
		return checkpointLocalObserverFilePin{}, errors.New("new observer socket inode is invalid")
	}
	return checkpointLocalObserverFilePin{path: path, dev: uint64(st.Dev), ino: st.Ino, fd: -1, parents: parents, trustRoot: config.trustRoot, fixtureAnchor: config.fixtureAnchor}, nil
}

func checkpointLocalObserverSocketCreatedStillPinned(pin checkpointLocalObserverFilePin) bool {
	if checkpointLocalObserverCheckParentPins(pin.parents) != nil {
		return false
	}
	var st unix.Stat_t
	err := unix.Lstat(pin.path, &st)
	return err == nil && st.Mode&unix.S_IFMT == unix.S_IFSOCK && st.Nlink == 1 && uint64(st.Dev) == pin.dev && st.Ino == pin.ino
}

func checkpointLocalObserverUnlinkSocket(pin checkpointLocalObserverFilePin) error {
	if len(pin.parents) == 0 || checkpointLocalObserverCheckParentPins(pin.parents) != nil || !checkpointLocalObserverSocketCreatedStillPinned(pin) {
		return errors.New("observer socket cleanup identity is uncertain; path preserved")
	}
	return unix.Unlinkat(pin.parents[len(pin.parents)-1].fd, filepath.Base(pin.path), 0)
}

func checkpointLocalObserverPeer(conn *net.UnixConn) (uid uint32, gid uint32, pid int, err error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, 0, err
	}
	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, 0, 0, err
	}
	if controlErr != nil || cred == nil {
		return 0, 0, 0, errors.New("SO_PEERCRED is unavailable")
	}
	return cred.Uid, cred.Gid, int(cred.Pid), nil
}

func checkpointLocalObserverOpenCurrent(pid int) (*checkpointHeldLocalProcess, error) {
	process, err := openCheckpointHeldLocalProcess(pid)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/proc", strconv.Itoa(pid)), &st); err != nil {
		process.close()
		return nil, err
	}
	if process.uid != st.Uid || process.start == 0 || process.namespace.Inode == 0 {
		process.close()
		return nil, errors.New("held process identity is incomplete")
	}
	return process, nil
}

func checkpointLocalObserverOpenCrossUID(pid int) (*checkpointHeldLocalProcess, error) {
	if pid <= 1 {
		return nil, errors.New("signed worker PID is invalid")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	start, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil {
		_ = unix.Close(pidfd)
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/proc", strconv.Itoa(pid)), &st); err != nil {
		_ = unix.Close(pidfd)
		return nil, err
	}
	// The unprivileged verifier deliberately does not open the worker's
	// namespace, executable, maps, or other ptrace-gated proc descriptors.
	process := &checkpointHeldLocalProcess{pid: pid, start: start, uid: st.Uid, pidfd: pidfd, nsfd: -1}
	if err := checkpointLocalPIDFDAlive(pidfd); err != nil {
		process.close()
		return nil, err
	}
	return process, nil
}

func checkpointLocalObserverIdentityOf(process *checkpointHeldLocalProcess) (CheckpointLocalObserverIdentity, error) {
	if process == nil || checkpointLocalPIDFDAlive(process.pidfd) != nil {
		return CheckpointLocalObserverIdentity{}, errors.New("process identity is no longer held alive")
	}
	gid, err := checkpointLocalObserverProcessGID(process.pid)
	if err != nil {
		return CheckpointLocalObserverIdentity{}, err
	}
	boot := checkpointLocalBootID()
	if boot == "" {
		return CheckpointLocalObserverIdentity{}, errors.New("local boot identity is unavailable")
	}
	return CheckpointLocalObserverIdentity{PID: process.pid, UID: process.uid, GID: gid, StartTicks: process.start, PIDNamespaceInode: process.namespace.Inode, ExecutablePath: process.exe, ExecutableSHA256: strings.ToLower(process.exeSHA256), ControlGroup: process.cgroup, BootID: boot}, nil
}

func checkpointLocalObserverProcessGID(pid int) (uint32, error) {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join("/proc", strconv.Itoa(pid)), &st); err != nil {
		return 0, err
	}
	return st.Gid, nil
}

func checkpointLocalObserverSameStat(a, b *unix.Stat_t) bool {
	return a != nil && b != nil && a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Mode == b.Mode && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
