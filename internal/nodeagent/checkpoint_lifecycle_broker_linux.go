//go:build linux

package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"vram-governor/internal/safefile"
	"vram-governor/internal/wsproto"
)

const checkpointPlanBrokerJournalVersion = 1

var checkpointPlanBrokerFixtureNameRE = regexp.MustCompile(`^vram-plan-relaunch-cpu-[0-9a-f]{16}$`)

var checkpointPlanBrokerMu sync.Mutex

func runCheckpointLifecycleBrokerPlatform(ctx context.Context, paths checkpointPlanBrokerPaths) error {
	if ctx == nil || ctx.Err() != nil || !fixedCheckpointPlanBrokerPathSet(paths) {
		return errors.New("fixed plan broker path contract is invalid")
	}
	if err := checkpointPlanBrokerRootDir(paths.RuntimeDir, 0o750); err != nil {
		return err
	}
	if _, err := os.Lstat(paths.Socket); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed plan broker socket path is already occupied")
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: paths.Socket, Net: "unix"})
	if err != nil {
		return fmt.Errorf("fixed plan broker socket could not be created: %w", err)
	}
	ownedSocket, statErr := os.Lstat(paths.Socket)
	if statErr != nil {
		_ = listener.Close()
		return errors.New("fixed plan broker socket identity is unavailable")
	}
	defer func() {
		_ = listener.Close()
		if current, err := os.Lstat(paths.Socket); err == nil && os.SameFile(ownedSocket, current) && current.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(paths.Socket)
		}
	}()
	stopPaths := checkpointPlanBrokerOwnedStopPaths(paths)
	_, _, err = loadOwnedStopNodeConfigAt(stopPaths)
	if err != nil {
		return errors.New("fixed plan broker node identity is unavailable")
	}
	uid, gid, err := checkpointOwnedStopPrincipal(stopPaths)
	if err != nil || uid == 0 || gid == 0 {
		return errors.New("fixed plan broker node principal is unavailable")
	}
	if err := checkpointPlanBrokerRuntimeDirectory(paths.RuntimeDir, gid); err != nil {
		return err
	}
	if err := os.Chown(paths.Socket, 0, int(gid)); err != nil {
		return errors.New("fixed plan broker socket group could not be pinned")
	}
	if err := os.Chmod(paths.Socket, 0o660); err != nil {
		return errors.New("fixed plan broker socket mode could not be pinned")
	}
	if err := checkpointPlanBrokerSocketIdentity(paths.Socket, gid); err != nil {
		return err
	}
	semaphore := make(chan struct{}, 4)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = listener.SetDeadline(time.Now().Add(time.Second))
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case semaphore <- struct{}{}:
			go func() {
				defer func() { <-semaphore; _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(checkpointPlanBrokerMaxTimeout))
				serveCheckpointPlanBrokerConnection(ctx, conn, paths, uid, gid)
			}()
		default:
			_ = conn.Close()
		}
	}
}

func fixedCheckpointPlanBrokerPathSet(paths checkpointPlanBrokerPaths) bool {
	if paths.privateFixture {
		return checkpointPlanBrokerPrivateFixturePathSet(paths)
	}
	fixed := fixedCheckpointPlanBrokerPaths()
	return paths.fixtureRoot == "" && paths.fixtureUnit == "" && paths.bindingObserver == nil && paths.faultInjector == nil && paths.Socket == fixed.Socket && paths.RuntimeDir == fixed.RuntimeDir && paths.Catalog == fixed.Catalog && paths.ActivePlan == fixed.ActivePlan && paths.PrivateKey == fixed.PrivateKey && paths.PublicKey == fixed.PublicKey && paths.Journal == fixed.Journal && paths.ReceiptDir == fixed.ReceiptDir && paths.StopPrivateKey == fixed.StopPrivateKey && paths.StopPublicKey == fixed.StopPublicKey && paths.StopReceiptDir == fixed.StopReceiptDir && paths.NodeConfig == fixed.NodeConfig && paths.NodeEnv == fixed.NodeEnv && paths.NodeState == fixed.NodeState && paths.NodeStateDir == fixed.NodeStateDir
}

func checkpointPlanBrokerOwnedStopPaths(paths checkpointPlanBrokerPaths) checkpointOwnedStopPaths {
	stop := fixedCheckpointOwnedStopPaths()
	if !checkpointPlanBrokerPrivateFixturePathSet(paths) {
		return stop
	}
	stop.NodeConfig = paths.NodeConfig
	stop.NodeEnv = paths.NodeEnv
	stop.NodeState = paths.NodeState
	stop.Socket = filepath.Join(paths.fixtureRoot, "run", "stop.sock")
	stop.PrivateKey = paths.StopPrivateKey
	stop.PublicKey = paths.StopPublicKey
	stop.ReceiptDir = paths.StopReceiptDir
	stop.SnapshotRoot = checkpointFixedSnapshotRoot
	stop.TrustedRoot = filepath.Join(paths.fixtureRoot, "var")
	stop.ConfigRoot = filepath.Join(paths.fixtureRoot, "etc")
	stop.StateDir = paths.NodeStateDir
	stop.NodeUID = paths.NodeUID
	stop.NodeGID = paths.NodeGID
	stop.principalPinned = true
	return stop
}

func checkpointPlanBrokerPrivateFixturePathSet(paths checkpointPlanBrokerPaths) bool {
	if !paths.privateFixture || os.Getenv("VRAM_PLAN_BROKER_CPU_OPT_IN") != "I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS" || filepath.Clean(paths.fixtureRoot) != paths.fixtureRoot || !filepath.IsAbs(paths.fixtureRoot) || filepath.Dir(paths.fixtureRoot) != os.TempDir() || !checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(paths.fixtureRoot)) || paths.NodeUID != 65534 || paths.NodeGID == 0 {
		return false
	}
	rootInfo, err := os.Lstat(paths.fixtureRoot)
	rootStat, ok := infoSys(rootInfo)
	if err != nil || !ok || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o711 || rootStat.Uid != 0 || rootStat.Nlink < 2 {
		return false
	}
	// The root-owned fixture anchor is search-only so the exact configured
	// unprivileged node principal can traverse to its group-pinned SOCK_STREAM
	// endpoint. Sensitive fixture material remains in stricter descendants.
	if euid := uint32(os.Geteuid()); euid != 0 && euid != paths.NodeUID {
		return false
	}
	if euid := uint32(os.Geteuid()); euid == paths.NodeUID && uint32(os.Getegid()) != paths.NodeGID {
		return false
	}
	for _, expected := range []struct {
		path string
		uid  uint32
		gid  uint32
		mode os.FileMode
	}{
		{filepath.Join(paths.fixtureRoot, "etc"), 0, 0, 0o755},
		{filepath.Join(paths.fixtureRoot, "var"), 0, 0, 0o711},
		{filepath.Join(paths.fixtureRoot, "var", "private"), 0, 0, 0o700},
		{filepath.Join(paths.fixtureRoot, "var", "public"), 0, 0, 0o755},
		{filepath.Join(paths.fixtureRoot, "var", "public", "receipts"), 0, paths.NodeGID, 0o750},
		{filepath.Join(paths.fixtureRoot, "var", "stop-private"), 0, 0, 0o700},
		{filepath.Join(paths.fixtureRoot, "var", "stop-public"), 0, paths.NodeGID, 0o750},
		{filepath.Join(paths.fixtureRoot, "var", "stop-public", "receipts"), 0, paths.NodeGID, 0o750},
		{filepath.Join(paths.fixtureRoot, "var", "node"), paths.NodeUID, paths.NodeGID, 0o700},
		{filepath.Join(paths.fixtureRoot, "run"), 0, paths.NodeGID, 0o750},
	} {
		info, statErr := os.Lstat(expected.path)
		stat, valid := infoSys(info)
		if statErr != nil || !valid || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != expected.uid || stat.Gid != expected.gid || info.Mode().Perm() != expected.mode {
			return false
		}
	}
	unit := filepath.Base(paths.fixtureRoot) + ".service"
	return paths.fixtureUnit == unit && paths.Socket == filepath.Join(paths.fixtureRoot, "run", "plan.sock") && paths.RuntimeDir == filepath.Join(paths.fixtureRoot, "run") &&
		paths.Catalog == filepath.Join(paths.fixtureRoot, "etc", "checkpoint-plan-catalog.json") && paths.ActivePlan == filepath.Join(paths.fixtureRoot, "etc", "active-plan.json") &&
		paths.PrivateKey == filepath.Join(paths.fixtureRoot, "var", "private", "ed25519.key") && paths.PublicKey == filepath.Join(paths.fixtureRoot, "var", "public", "ed25519.pub") &&
		paths.Journal == filepath.Join(paths.fixtureRoot, "var", "private", "operations.json") && paths.ReceiptDir == filepath.Join(paths.fixtureRoot, "var", "public", "receipts") &&
		paths.StopPrivateKey == filepath.Join(paths.fixtureRoot, "var", "stop-private", "ed25519.key") && paths.StopPublicKey == filepath.Join(paths.fixtureRoot, "var", "stop-public", "ed25519.pub") && paths.StopReceiptDir == filepath.Join(paths.fixtureRoot, "var", "stop-public", "receipts") &&
		paths.NodeConfig == filepath.Join(paths.fixtureRoot, "etc", "node-agent.yaml") && paths.NodeEnv == filepath.Join(paths.fixtureRoot, "etc", "node-agent.env") &&
		paths.NodeState == filepath.Join(paths.fixtureRoot, "var", "node", "commands.json") && paths.NodeStateDir == filepath.Join(paths.fixtureRoot, "var", "node")
}

func checkpointPlanBrokerPrivateFixturePath(path string, paths checkpointPlanBrokerPaths, relative string) bool {
	return checkpointPlanBrokerPrivateFixturePathSet(paths) && filepath.Clean(path) == filepath.Join(paths.fixtureRoot, filepath.FromSlash(relative))
}

func checkpointPlanBrokerUnitName(paths checkpointPlanBrokerPaths) string {
	if checkpointPlanBrokerPrivateFixturePathSet(paths) {
		return paths.fixtureUnit
	}
	return checkpointPlanBrokerUnit
}

func checkpointPlanBrokerFixtureFault(paths checkpointPlanBrokerPaths, boundary string) bool {
	return paths.privateFixture && checkpointPlanBrokerPrivateFixturePathSet(paths) && paths.faultInjector != nil && paths.faultInjector(boundary)
}

func checkpointPlanBrokerRootDir(path string, mode os.FileMode) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm() != mode {
		return errors.New("fixed plan broker directory is absent or unsafe")
	}
	return nil
}

func checkpointPlanBrokerTrustedDirectory(path string) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("fixed plan broker trusted directory is unavailable or writable by an untrusted principal")
	}
	return nil
}

func checkpointPlanBrokerRuntimeDirectory(path string, gid uint32) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != gid || info.Mode().Perm() != 0o750 {
		return errors.New("fixed plan broker runtime directory owner or mode is invalid")
	}
	return nil
}

func checkpointPlanBrokerSocketIdentity(path string, gid uint32) error {
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || info.Mode()&os.ModeSocket == 0 || stat.Uid != 0 || stat.Gid != gid || info.Mode().Perm() != 0o660 || stat.Nlink != 1 {
		return errors.New("fixed plan broker socket ownership or mode is invalid")
	}
	return nil
}

func serveCheckpointPlanBrokerConnection(ctx context.Context, conn *net.UnixConn, paths checkpointPlanBrokerPaths, uid, gid uint32) {
	response := checkpointPlanBrokerResponse{Error: "request rejected"}
	defer func() {
		raw, err := json.Marshal(response)
		if err == nil && len(raw) <= checkpointPlanRelaunchMaxFrame {
			_, _ = conn.Write(append(raw, '\n'))
		}
	}()
	if ctx == nil || ctx.Err() != nil || conn == nil {
		return
	}
	if err := checkpointPlanBrokerPeer(conn, uid, gid); err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(conn, checkpointPlanRelaunchMaxFrame+1))
	if err != nil || len(raw) == 0 || len(raw) > checkpointPlanRelaunchMaxFrame || !bytes.HasSuffix(raw, []byte("\n")) {
		return
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	if rejectDuplicateJSONKeys(raw) != nil {
		return
	}
	var request checkpointPlanBrokerRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || len(request.Command) == 0 || len(request.Command) > checkpointPlanRelaunchMaxFrame {
		return
	}
	var extra any
	if decoder.Decode(&extra) == nil {
		return
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(canonical, raw) || rejectDuplicateJSONKeys(request.Command) != nil {
		return
	}
	var command wsproto.CommandPayload
	if json.Unmarshal(request.Command, &command) != nil || (command.Command != checkpointPlanRelaunchUrgentCommand && command.Command != checkpointPlanRelaunchVictimCommand && command.Command != checkpointPlanRelaunchQueryCommand) {
		return
	}
	if err := wsproto.ValidatePlanRelaunchCommandArgs(command.Command, command.Args); err != nil {
		return
	}
	if err := validateCheckpointPlanRelaunchCommandTime(command, time.Now().UTC()); err != nil {
		return
	}
	commandCtx, cancel := context.WithDeadline(ctx, command.ExpiresAt)
	defer cancel()
	result, err := processCheckpointPlanBrokerCommand(commandCtx, paths, request.Command, command)
	if err != nil {
		return
	}
	response = result
}

func checkpointPlanBrokerPeer(conn *net.UnixConn, uid, gid uint32) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || credential == nil || credential.Uid != uid || credential.Gid != gid {
		return errors.New("plan broker peer principal is not the fixed node agent")
	}
	return nil
}

type checkpointPlanBrokerRequestHalfCloser interface {
	Write([]byte) (int, error)
	CloseWrite() error
}

func writeCheckpointPlanBrokerRequest(conn checkpointPlanBrokerRequestHalfCloser, request []byte) error {
	if conn == nil || len(request) == 0 || len(request) >= checkpointPlanRelaunchMaxFrame {
		return errors.New("fixed plan broker request frame is invalid")
	}
	frame := make([]byte, len(request)+1)
	copy(frame, request)
	frame[len(request)] = '\n'
	n, err := conn.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	if err := conn.CloseWrite(); err != nil {
		return fmt.Errorf("fixed plan broker request half-close failed: %w", err)
	}
	return nil
}

func invokeCheckpointPlanBroker(ctx context.Context, paths checkpointPlanBrokerPaths, request []byte) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || !fixedCheckpointPlanBrokerPathSet(paths) || len(request) == 0 || len(request) >= checkpointPlanRelaunchMaxFrame {
		return nil, errors.New("fixed plan broker request is invalid")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", paths.Socket)
	if err != nil {
		return nil, err
	}
	conn, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("plan broker endpoint is not a Unix socket")
	}
	defer conn.Close()
	if err := checkpointPlanBrokerServerPeer(conn); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(checkpointPlanBrokerMaxTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if err := writeCheckpointPlanBrokerRequest(conn, request); err != nil {
		return nil, err
	}
	response, err := io.ReadAll(io.LimitReader(conn, checkpointPlanRelaunchMaxFrame+1))
	if err != nil || len(response) == 0 || len(response) > checkpointPlanRelaunchMaxFrame || !bytes.HasSuffix(response, []byte("\n")) {
		return nil, errors.New("fixed plan broker reply is unavailable or oversized")
	}
	return bytes.TrimSuffix(response, []byte("\n")), nil
}

func checkpointPlanBrokerServerPeer(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if controlErr != nil || credential == nil || credential.Uid != 0 || credential.Gid != 0 {
		return errors.New("fixed plan broker peer is not root")
	}
	return nil
}

// processCheckpointPlanBrokerCommand performs no caller-selected process or
// path operation. It first authenticates the exact fsynced node envelope,
// root-key pins, stop receipt, catalog entry and fence; only then may it enter
// the fixed plan CAS/start transaction.
func processCheckpointPlanBrokerCommand(ctx context.Context, paths checkpointPlanBrokerPaths, wire []byte, command wsproto.CommandPayload) (checkpointPlanBrokerResponse, error) {
	if ctx == nil || ctx.Err() != nil || !fixedCheckpointPlanBrokerPathSet(paths) || len(wire) == 0 || !checkpointPlanRelaunchIsCommand(command.Command) {
		return checkpointPlanBrokerResponse{}, errors.New("fixed plan broker command is unavailable")
	}
	// Root-side authority and journal validation are kept in a distinct
	// implementation from the owned-stop validator. The operation engine is
	// completed below this admission boundary; rejecting before any side effect
	// is mandatory whenever one of its persistent roots is missing.
	return reconcileCheckpointPlanBrokerOperation(ctx, paths, wire, command)
}

func reconcileCheckpointPlanBrokerOperation(ctx context.Context, paths checkpointPlanBrokerPaths, wire []byte, command wsproto.CommandPayload) (checkpointPlanBrokerResponse, error) {
	checkpointPlanBrokerMu.Lock()
	defer checkpointPlanBrokerMu.Unlock()
	if command.Command == checkpointPlanRelaunchQueryCommand {
		return reconcileCheckpointPlanBrokerQuery(ctx, paths, wire, command)
	}
	verified, err := validateCheckpointPlanRelaunchNodeIntent(ctx, paths, wire, command)
	if err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	rootPrivate, rootPublic, err := loadCheckpointPlanBrokerSigningKey(paths)
	if err != nil || !bytes.Equal(rootPublic, verified.RootPublicKey) {
		return checkpointPlanBrokerResponse{}, errors.New("root broker signer is not the node-pinned keypair")
	}
	verified.RootPrivateKey = append(ed25519.PrivateKey(nil), rootPrivate...)
	journal, err := loadCheckpointPlanBrokerJournal(paths.Journal, paths)
	if errors.Is(err, os.ErrNotExist) {
		journal = checkpointPlanBrokerJournal{Version: checkpointPlanBrokerJournalVersion, Operations: make(map[string]checkpointPlanBrokerOperation)}
		err = nil
	}
	if err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	operationID := fmt.Sprint(command.Args["operation_id"])
	step, err := planRelaunchCommandStep(command)
	if err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	entry := journal.Operations[operationID]
	if command.Command == checkpointPlanRelaunchQueryCommand {
		if entry.Operation.OperationID != operationID || entry.Operation.AcceleratorID != command.Args["accelerator_id"] || entry.Operation.Fence != int64FromArg(command.Args["fencing_token"]) {
			return checkpointPlanBrokerResponse{}, errors.New("root broker has no exact linked operation")
		}
		if recorded, ok := entry.Steps[step]; ok && recorded.Status == "acknowledged" && len(recorded.Receipt) != 0 && recorded.ReceiptSHA256 == sha256Hex(recorded.Receipt) {
			return checkpointPlanBrokerResponse{Receipt: append([]byte(nil), recorded.Receipt...)}, nil
		}
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if recorded, exists := entry.Steps[step]; exists {
		if recorded.CommandID != command.ID || recorded.IdempotencyKey != command.IdempotencyKey || recorded.EnvelopeSHA256 != sha256Hex(wire) || !bytes.Equal(recorded.OriginalEnvelope, wire) {
			return checkpointPlanBrokerResponse{}, errors.New("root broker step identity was already consumed")
		}
		if recorded.Status == "acknowledged" && len(recorded.Receipt) > 0 {
			return checkpointPlanBrokerResponse{Receipt: append([]byte(nil), recorded.Receipt...)}, nil
		}
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if command.Command == checkpointPlanRelaunchVictimCommand {
		urgent, ok := entry.Steps["urgent_load"]
		if !ok || urgent.Status != "acknowledged" || len(urgent.Receipt) == 0 || entry.Operation.VictimCatalogID != fmt.Sprint(command.Args["catalog_id"]) || entry.Operation.UrgentCatalogID == "" {
			return checkpointPlanBrokerResponse{}, errors.New("victim reload lacks the exact urgent terminal receipt")
		}
		_, public, keyErr := loadCheckpointPlanBrokerSigningKey(paths)
		urgentReceipt, verifyErr := verifyCheckpointPlanRelaunchReceipt(urgent.Receipt, public, urgent.OriginalEnvelope, verified.Config.CommandSigningSecret)
		if keyErr != nil || verifyErr != nil || urgent.ReceiptSHA256 != sha256Hex(urgent.Receipt) || urgentReceipt.Step != "urgent_load" || urgentReceipt.CatalogID != entry.Operation.UrgentCatalogID || urgentReceipt.LinkedCatalogID != entry.Operation.VictimCatalogID || urgentReceipt.OperationID != operationID || urgentReceipt.FencingToken != entry.Operation.Fence || urgentReceipt.CatalogSHA256 != verified.CatalogSHA256 || entry.Operation.TargetID != command.Args["target_id"] || entry.Operation.WorkloadID != command.Args["workload_id"] || entry.Operation.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) || entry.Operation.RecoveryEpoch != command.Args["recovery_epoch"] {
			return checkpointPlanBrokerResponse{}, errors.New("urgent receipt or operation journal does not authorize the exact victim reload")
		}
		if urgentReceipt.InvocationID != verified.PriorReceipt.InvocationID || urgentReceipt.MainPID != verified.PriorReceipt.WorkerPID || urgentReceipt.CurrentIncarnation != verified.PriorReceipt.ManagedCurrentIncarnation || urgentReceipt.CustodyBindingSHA256 != verified.PriorReceipt.CustodyBindingSHA256 || urgentReceipt.Alias != verified.PriorReceipt.ModelAlias || urgentReceipt.PlanSHA256 != verified.PriorReceipt.ManagedPlanSHA256 || entry.PlanSHA256 != urgentReceipt.PlanSHA256 {
			return checkpointPlanBrokerResponse{}, errors.New("urgent stop receipt does not identify the terminal urgent process")
		}
	} else if len(entry.Steps) != 0 {
		return checkpointPlanBrokerResponse{}, errors.New("urgent load is not the first plan relaunch step")
	}
	if err := checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, verified.PriorReceipt); err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	acceptedTime := time.Now().UTC()
	if acceptedTime.After(verified.Command.ExpiresAt) {
		return checkpointPlanBrokerResponse{}, errors.New("plan relaunch expired before the root intent was accepted")
	}
	acceptedAt := acceptedTime.Format(time.RFC3339Nano)
	if err := verifyCheckpointPlanBrokerStoppedObservation(verified.Stopped, paths, verified.PriorReceipt); err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	activeRaw, activeInfo, err := readPlanBrokerFile(paths.ActivePlan, checkpointLaunchPlanMaxBytes, 0)
	if err != nil {
		return checkpointPlanBrokerResponse{}, errors.New("fixed active plan cannot be pinned")
	}
	activeDigest := sha256Hex(activeRaw)
	if command.Command == checkpointPlanRelaunchUrgentCommand && activeDigest != verified.PriorReceipt.ManagedPlanSHA256 {
		return checkpointPlanBrokerResponse{}, errors.New("stopped victim plan digest differs from the linked stop receipt")
	}
	if command.Command == checkpointPlanRelaunchVictimCommand {
		urgent := entry.Steps["urgent_load"]
		urgentReceipt, verifyErr := verifyCheckpointPlanRelaunchReceipt(urgent.Receipt, verified.RootPublicKey, urgent.OriginalEnvelope, verified.Config.CommandSigningSecret)
		if verifyErr != nil || activeDigest != urgentReceipt.PlanSHA256 {
			return checkpointPlanBrokerResponse{}, errors.New("active urgent plan differs from its signed terminal receipt")
		}
	}
	activePlan, err := ParseCheckpointLaunchPlan(activeRaw)
	if err != nil || validateCheckpointPlanBrokerPlan(paths, activePlan) != nil || activeInfo == nil {
		return checkpointPlanBrokerResponse{}, errors.New("fixed active plan is not a supported v2 plan")
	}
	selected := verified.CatalogEntries[fmt.Sprint(command.Args["catalog_id"])]
	newPlan, err := base64.StdEncoding.DecodeString(selected.PlanBase64)
	if err != nil || sha256Hex(newPlan) != selected.PlanSHA256 {
		return checkpointPlanBrokerResponse{}, errors.New("approved plan bytes are unavailable")
	}
	parsedNew, err := ParseCheckpointLaunchPlan(newPlan)
	if err != nil || parsedNew.Version != checkpointLaunchPlanVersion2 || validateCheckpointPlanBrokerPlan(paths, parsedNew) != nil {
		return checkpointPlanBrokerResponse{}, errors.New("approved plan is not a fixed v2 launch plan")
	}
	victimCatalogID := fmt.Sprint(command.Args["linked_catalog_id"])
	if command.Command == checkpointPlanRelaunchVictimCommand {
		victimCatalogID = fmt.Sprint(command.Args["catalog_id"])
	}
	victimEntry, victimExists := verified.CatalogEntries[victimCatalogID]
	if !victimExists {
		return checkpointPlanBrokerResponse{}, errors.New("original victim catalog is no longer approved")
	}
	victimPlanRaw, err := base64.StdEncoding.DecodeString(victimEntry.PlanBase64)
	if err != nil {
		return checkpointPlanBrokerResponse{}, errors.New("original victim plan bytes are unavailable")
	}
	victimPlan, err := ParseCheckpointLaunchPlan(victimPlanRaw)
	if err != nil || victimPlan.Version != checkpointLaunchPlanVersion2 || validateCheckpointPlanBrokerPlan(paths, victimPlan) != nil {
		return checkpointPlanBrokerResponse{}, errors.New("original victim plan is unsupported")
	}
	if command.Command == checkpointPlanRelaunchUrgentCommand && (activeDigest != victimEntry.PlanSHA256 || !bytes.Equal(activeRaw, victimPlanRaw)) {
		return checkpointPlanBrokerResponse{}, errors.New("stopped victim plan is not byte-identical to its approved catalog entry")
	}
	if activePlan.Alias != verified.PriorReceipt.ModelAlias || ((parsedNew.Alias == activePlan.Alias || parsedNew.Model.SHA256 == activePlan.Model.SHA256) && command.Command == checkpointPlanRelaunchUrgentCommand) {
		return checkpointPlanBrokerResponse{}, errors.New("plan rotation does not preserve victim or urgent identity separation")
	}
	if command.Command == checkpointPlanRelaunchVictimCommand && (parsedNew.Alias != victimPlan.Alias || selected.CatalogID != entry.Operation.VictimCatalogID) {
		return checkpointPlanBrokerResponse{}, errors.New("victim reload catalog differs from the original victim plan")
	}
	if command.Command == checkpointPlanRelaunchVictimCommand && (entry.VictimPlanSHA256 != selected.PlanSHA256 || entry.UrgentAlias == "" || parsedNew.Alias == entry.UrgentAlias || parsedNew.Model.SHA256 == entry.UrgentModelSHA256) {
		return checkpointPlanBrokerResponse{}, errors.New("victim reload does not restore the exact catalog-pinned victim distinct from urgent model")
	}
	if entry.Operation.OperationID == "" {
		entry.Operation = checkpointPlanRelaunchOperation{OperationID: operationID, TargetID: verified.Command.Args["target_id"].(string), AcceleratorID: verified.Command.Args["accelerator_id"].(string), WorkloadID: verified.Command.Args["workload_id"].(string), WorkloadRevision: int64FromArg(verified.Command.Args["workload_revision"]), RecoveryEpoch: verified.Command.Args["recovery_epoch"].(string), Fence: int64FromArg(verified.Command.Args["fencing_token"]), VictimCatalogID: verified.Command.Args["linked_catalog_id"].(string), UrgentCatalogID: verified.Command.Args["catalog_id"].(string), Steps: make(map[string]checkpointPlanRelaunchStep)}
	}
	entry.VictimAlias = victimPlan.Alias
	entry.VictimPlanSHA256 = victimEntry.PlanSHA256
	if command.Command == checkpointPlanRelaunchUrgentCommand {
		entry.UrgentAlias = parsedNew.Alias
		entry.UrgentModelSHA256 = parsedNew.Model.SHA256
	}
	if command.Command == checkpointPlanRelaunchVictimCommand && entry.UrgentAlias == "" {
		return checkpointPlanBrokerResponse{}, errors.New("root journal lost the urgent plan identity")
	}
	if entry.Steps == nil {
		entry.Steps = make(map[string]checkpointPlanRelaunchStep)
	}
	entry.PriorPlanSHA256 = activeDigest
	entry.PriorInvocation = verified.PriorReceipt.InvocationID
	entry.CatalogSHA256 = verified.CatalogSHA256
	entry.PlanSHA256 = selected.PlanSHA256
	entry.Stage = step + "_prepared"
	entry.Steps[step] = checkpointPlanRelaunchStep{CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, EnvelopeSHA256: sha256Hex(wire), OriginalEnvelope: append([]byte(nil), wire...), SigningMaterialSHA256: verified.SigningDigest, AcceptedAt: acceptedAt, Status: "pending"}
	journal.Operations[operationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{}, errors.New("root broker intent could not be made durable")
	}
	if checkpointPlanBrokerFixtureFault(paths, "intent_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	currentCatalog, currentCatalogInfo, catalogErr := readPlanBrokerFile(paths.Catalog, checkpointPlanCatalogMaxBytes, 0)
	if catalogErr != nil || currentCatalogInfo == nil || !os.SameFile(verified.CatalogInfo, currentCatalogInfo) || !sameCheckpointFileSnapshot(verified.CatalogInfo, currentCatalogInfo) || sha256Hex(currentCatalog) != verified.CatalogSHA256 {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if err := publishCheckpointPlanBrokerPlan(ctx, paths, paths.ActivePlan, activeRaw, activeInfo, newPlan, activeDigest, verified.PriorReceipt); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "plan_published") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	entry.Stage = step + "_published"
	entry.PriorPlanSHA256 = activeDigest
	journal.Operations[operationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "published_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	entry.Stage = step + "_start_requested"
	journal.Operations[operationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "start_requested_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if verifyCheckpointPlanBrokerStartState(ctx, paths, selected.PlanSHA256, verified.PriorReceipt) != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if _, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "start", checkpointPlanBrokerUnitName(paths)); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "systemd_start_returned") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	entry.Stage = step + "_start_accepted"
	journal.Operations[operationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "start_accepted_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	binding, err := awaitCheckpointPlanBrokerBinding(ctx, paths, parsedNew, selected.PlanSHA256, verified.PriorReceipt.InvocationID)
	if err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "binding_observed") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	receipt := checkpointPlanRelaunchReceipt{Version: 1, NodeID: verified.Command.NodeID, OperationID: operationID, Step: step, CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, OriginalEnvelopeSHA256: sha256Hex(wire), SigningMaterialSHA256: verified.SigningDigest, RecoveryEpoch: verified.Command.Args["recovery_epoch"].(string), AcceleratorID: verified.Command.Args["accelerator_id"].(string), FencingToken: int64FromArg(verified.Command.Args["fencing_token"]), TargetID: verified.Command.Args["target_id"].(string), WorkloadID: verified.Command.Args["workload_id"].(string), WorkloadRevision: int64FromArg(verified.Command.Args["workload_revision"]), CatalogID: selected.CatalogID, CatalogSHA256: verified.CatalogSHA256, PlanSHA256: selected.PlanSHA256, PriorReceiptSHA256: verified.PriorReceiptSHA256, PriorInvocationID: verified.PriorReceipt.InvocationID, AcceptedAt: acceptedAt, InvocationID: binding.Association.Invocation, MainPID: binding.Association.Identity.PID, CurrentIncarnation: binding.CurrentIncarnation, CustodyBindingSHA256: binding.CustodyBindingSHA256, Alias: binding.Alias, SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if step == "urgent_load" {
		receipt.LinkedCatalogID = entry.Operation.VictimCatalogID
	}
	unsigned, _ := json.Marshal(receipt)
	receipt.Signature = hex.EncodeToString(ed25519.Sign(verified.RootPrivateKey, checkpointPlanRelaunchSigningMaterial(unsigned)))
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if _, verifyErr := verifyCheckpointPlanRelaunchReceipt(receiptRaw, verified.RootPublicKey, wire, verified.Config.CommandSigningSecret); verifyErr != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if err := writeCheckpointPlanBrokerReceipt(paths, receiptRaw, verified.NodeGID); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "receipt_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	stepRecord := entry.Steps[step]
	stepRecord.Status = "acknowledged"
	stepRecord.Receipt = append([]byte(nil), receiptRaw...)
	stepRecord.ReceiptSHA256 = sha256Hex(receiptRaw)
	entry.Steps[step] = stepRecord
	entry.Stage = step + "_acknowledged"
	entry.PlanSHA256 = selected.PlanSHA256
	entry.CatalogSHA256 = verified.CatalogSHA256
	entry.PriorInvocation = binding.Association.Invocation
	journal.Operations[operationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "acknowledged_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	return checkpointPlanBrokerResponse{Receipt: receiptRaw}, nil
}

type verifiedPlanBrokerIntent struct {
	Config             *Config
	Command            wsproto.CommandPayload
	Pending            pendingCommand
	Stopped            checkpointPlanBrokerStoppedState
	PriorReceipt       ownedStopReceipt
	PriorReceiptSHA256 string
	CatalogEntries     map[string]checkpointPlanCatalogEntry
	CatalogSHA256      string
	CatalogInfo        os.FileInfo
	RootPublicKey      []byte
	RootPrivateKey     ed25519.PrivateKey
	SigningDigest      string
	NodeGID            uint32
}

type checkpointPlanBrokerStoppedState struct {
	MainPID      int
	Invocation   string
	ControlGroup string
	Active       string
	Sub          string
	Load         string
}

func verifyCheckpointPlanBrokerPriorStopResult(state commandStatePayload, paths checkpointPlanBrokerPaths, command wsproto.CommandPayload, operation ownedStopOperationState, stopStep ownedStopStepState, receiptRaw []byte, pinnedPublic ed25519.PublicKey, secret string) error {
	priorID := fmt.Sprint(command.Args["prior_command_id"])
	priorKey := fmt.Sprint(command.Args["prior_idempotency_key"])
	priorStep := "victim_stop"
	if command.Command == checkpointPlanRelaunchVictimCommand {
		priorStep = "urgent_stop"
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	operationID := fmt.Sprint(command.Args["operation_id"])
	fence := int64FromArg(command.Args["fencing_token"])
	joinedStep, joined := operation.Steps[priorStep]
	if priorID == "" || priorKey == "" || len(pinnedPublic) != ed25519.PublicKeySize || operation.OperationID != operationID || operation.AcceleratorID != accelerator || operation.Fence != fence || operation.RecoveryEpoch != command.Args["recovery_epoch"] || !operation.UsedOperationIDs[operationID] || !joined || joinedStep.Status != stopStep.Status || joinedStep.CommandID != stopStep.CommandID || joinedStep.IdempotencyKey != stopStep.IdempotencyKey || joinedStep.EnvelopeSHA256 != stopStep.EnvelopeSHA256 || joinedStep.ReceiptSHA256 != stopStep.ReceiptSHA256 || !bytes.Equal(joinedStep.PinnedRootStopPublicKey, stopStep.PinnedRootStopPublicKey) || stopStep.Status != "acknowledged" || stopStep.CommandID != priorID || stopStep.IdempotencyKey != priorKey || stopStep.ReceiptSHA256 != command.Args["prior_receipt_sha256"] || stopStep.EnvelopeSHA256 == "" || !bytes.Equal(stopStep.PinnedRootStopPublicKey, pinnedPublic) {
		return errors.New("prior root stop operation is not the exact durable predecessor")
	}
	result, ok := state.Results[priorID]
	if !ok || result.ID != priorID || result.NodeID != command.NodeID || !result.OK || result.Result == nil {
		return errors.New("durable prior stop result is unavailable")
	}
	encodedOriginal, originalOK := result.Result["original_envelope"].(string)
	encodedPublic, publicOK := result.Result["pinned_root_public_key"].(string)
	resultReceipt, receiptOK := result.Result["receipt"].(string)
	resultDigest, digestOK := result.Result["receipt_sha256"].(string)
	originalWire, originalErr := base64.StdEncoding.DecodeString(encodedOriginal)
	resultPublic, publicErr := base64.StdEncoding.DecodeString(encodedPublic)
	if !originalOK || !publicOK || !receiptOK || !digestOK || originalErr != nil || publicErr != nil || len(originalWire) == 0 || len(originalWire) > 16<<10 || len(resultReceipt) == 0 || len(resultReceipt) > 16<<10 || !bytes.Equal(resultPublic, pinnedPublic) || resultDigest != sha256Hex(receiptRaw) || resultDigest != stopStep.ReceiptSHA256 || !bytes.Equal([]byte(resultReceipt), receiptRaw) || sha256Hex(originalWire) != stopStep.EnvelopeSHA256 {
		return errors.New("durable prior stop result no longer matches its pinned command and receipt")
	}
	var original wsproto.CommandPayload
	if rejectDuplicateJSONKeys(originalWire) != nil || json.Unmarshal(originalWire, &original) != nil || wsproto.ValidateOwnedStopCommandArgs(original.Command, original.Args) != nil || !wsproto.VerifyCommand(original, []byte(secret)) {
		return errors.New("durable prior stop command is invalid")
	}
	canonicalOriginal, err := wsproto.CanonicalCommandEnvelope(original)
	if err != nil || result.Result["action"] != original.Command || original.Command != "llm_displacement_stop" || !bytes.Equal(canonicalOriginal, originalWire) || original.ID != priorID || original.IdempotencyKey != priorKey || original.NodeID != command.NodeID || original.Args["operation_id"] != operationID || original.Args["step_id"] != priorStep || original.Args["accelerator_id"] != accelerator || int64FromArg(original.Args["fencing_token"]) != fence || original.Args["recovery_epoch"] != command.Args["recovery_epoch"] || original.Args["target_id"] != command.Args["target_id"] || original.Args["workload_id"] != command.Args["workload_id"] || int64FromArg(original.Args["workload_revision"]) != int64FromArg(command.Args["workload_revision"]) {
		return errors.New("durable prior stop command differs from the linked plan request")
	}
	if err := verifyOwnedStopReceipt(receiptRaw, pinnedPublic, originalWire, secret); err != nil {
		return errors.New("durable prior stop receipt failed its exact command join")
	}
	var receipt ownedStopReceipt
	if json.Unmarshal(receiptRaw, &receipt) != nil || receipt.WorkerPID <= 1 || receipt.WorkerStartTicks == 0 || !receipt.SignalSent || !receipt.ReleaseTerminal || receipt.ControlGroup != filepath.Join("/system.slice", checkpointPlanBrokerUnitName(paths)) {
		return errors.New("prior stop receipt lacks exact terminal incarnation authority")
	}
	return nil
}

type checkpointPlanBrokerColdStopIO struct {
	readPublicKey func(string, checkpointOwnedStopPaths) ([]byte, error)
	lstat         func(string) (os.FileInfo, error)
	pathChain     func(string, checkpointOwnedStopPaths, bool) error
	readReceipt   func(string, int64, os.FileMode) ([]byte, os.FileInfo, error)
	processStart  func(int) error
}

func checkpointPlanBrokerColdPriorStopReceipt(paths checkpointPlanBrokerPaths, state commandStatePayload, command wsproto.CommandPayload, cfg *Config) (ownedStopReceipt, error) {
	if cfg == nil {
		return ownedStopReceipt{}, errors.New("node configuration is unavailable for prior stop recovery")
	}
	fixedIO := checkpointPlanBrokerColdStopIO{
		readPublicKey: readPinnedRootStopPublicKeyAt,
		lstat:         os.Lstat,
		pathChain:     checkpointOwnedStopPathChainAt,
		readReceipt:   readPlanBrokerFile,
		processStart: func(pid int) error {
			_, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
			return err
		},
	}
	return checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, state, command, cfg.CommandSigningSecret, fixedIO)
}

// The wrapper above always passes the fixed filesystem and /proc readers. This
// private reducer lets deterministic tests exercise the same key/path/owner/
// inode/currentness decisions without creating a privileged filesystem tree.
func checkpointPlanBrokerColdPriorStopReceiptWithIO(paths checkpointPlanBrokerPaths, state commandStatePayload, command wsproto.CommandPayload, secret string, io checkpointPlanBrokerColdStopIO) (ownedStopReceipt, error) {
	var receipt ownedStopReceipt
	if io.readPublicKey == nil || io.lstat == nil || io.pathChain == nil || io.readReceipt == nil || io.processStart == nil {
		return receipt, errors.New("cold recovery owned IO is unavailable")
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	priorID := fmt.Sprint(command.Args["prior_command_id"])
	stepID := "victim_stop"
	if command.Command == checkpointPlanRelaunchVictimCommand {
		stepID = "urgent_stop"
	}
	operation, ok := state.OwnedStopOperations[accelerator]
	stopStep, stepOK := operation.Steps[stepID]
	if !ok || !stepOK || priorID == "" {
		return receipt, errors.New("cold recovery lost the exact prior stop operation")
	}
	stopPaths := checkpointPlanBrokerOwnedStopPaths(paths)
	public, err := io.readPublicKey(stopPaths.PublicKey, stopPaths)
	if err != nil {
		return receipt, errors.New("cold recovery root stop public key is unavailable")
	}
	if len(public) != ed25519.PublicKeySize || !bytes.Equal(public, stopStep.PinnedRootStopPublicKey) {
		return receipt, errors.New("cold recovery root stop key pin changed")
	}
	path := filepath.Join(stopPaths.ReceiptDir, ownedStopReceiptFilename(priorID))
	dirInfo, dirErr := io.lstat(stopPaths.ReceiptDir)
	dirStat, dirOK := infoSys(dirInfo)
	if dirErr != nil || !dirOK || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirStat.Uid != 0 || dirStat.Gid != stopPaths.NodeGID || dirInfo.Mode().Perm() != 0o750 || io.pathChain(path, stopPaths, true) != nil {
		return receipt, errors.New("cold recovery prior stop receipt directory is unsafe")
	}
	raw, info, err := io.readReceipt(path, 16<<10, 0o640)
	if errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("cold recovery prior stop receipt is missing")
	}
	if err != nil || info == nil {
		return receipt, errors.New("cold recovery prior stop receipt is unavailable or changed")
	}
	stat, statOK := infoSys(info)
	if !statOK || stat.Uid != 0 || stat.Gid != stopPaths.NodeGID || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o640 || info.Size() <= 0 || info.Size() > 16<<10 || stat.Nlink != 1 || int64(len(raw)) != info.Size() {
		return receipt, errors.New("cold recovery prior stop receipt ownership or inode is unsafe")
	}
	if sha256Hex(raw) != fmt.Sprint(command.Args["prior_receipt_sha256"]) || rejectDuplicateJSONKeys(raw) != nil {
		return receipt, errors.New("cold recovery prior stop receipt is unavailable or changed")
	}
	var terminalReceipt ownedStopReceipt
	if json.Unmarshal(raw, &terminalReceipt) != nil || terminalReceipt.WorkerPID <= 1 {
		return receipt, errors.New("cold recovery original worker identity is unavailable")
	}
	procErr := io.processStart(terminalReceipt.WorkerPID)
	return verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, command, operation, stopStep, raw, public, secret, procErr)
}

// verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence is the fixed internal
// reducer after the deployed wrapper has re-read the pinned key and exact
// identity-held receipt file. The injected process result is private to this
// package so deterministic controls can prove fail-closed terminal behavior.
func verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state commandStatePayload, paths checkpointPlanBrokerPaths, command wsproto.CommandPayload, operation ownedStopOperationState, stopStep ownedStopStepState, raw []byte, public ed25519.PublicKey, secret string, procErr error) (ownedStopReceipt, error) {
	var receipt ownedStopReceipt
	if len(raw) == 0 || len(raw) > 16<<10 || rejectDuplicateJSONKeys(raw) != nil {
		return receipt, errors.New("cold recovery prior stop receipt is malformed")
	}
	if err := verifyCheckpointPlanBrokerPriorStopResult(state, paths, command, operation, stopStep, raw, public, secret); err != nil {
		return receipt, err
	}
	if json.Unmarshal(raw, &receipt) != nil || checkpointPlanBrokerOriginalWorkerTerminalResult(receipt, procErr) != nil {
		return ownedStopReceipt{}, errors.New("cold recovery original worker terminal proof is unavailable")
	}
	return receipt, nil
}

func validateCheckpointPlanRelaunchNodeIntent(ctx context.Context, paths checkpointPlanBrokerPaths, wire []byte, command wsproto.CommandPayload) (verifiedPlanBrokerIntent, error) {
	var out verifiedPlanBrokerIntent
	stopPaths := checkpointPlanBrokerOwnedStopPaths(paths)
	cfg, configDigest, err := loadOwnedStopNodeConfigAt(stopPaths)
	if err != nil || cfg == nil || command.NodeID != cfg.NodeID || !wsproto.VerifyCommand(command, []byte(cfg.CommandSigningSecret)) {
		return out, errors.New("original plan relaunch command authentication failed")
	}
	canonical, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil || !bytes.Equal(canonical, wire) || validateCheckpointPlanRelaunchCommandTime(command, time.Now().UTC()) != nil {
		return out, errors.New("original plan relaunch command is noncanonical or stale")
	}
	if err := wsproto.ValidatePlanRelaunchCommandArgs(command.Command, command.Args); err != nil || command.Command == checkpointPlanRelaunchQueryCommand {
		return out, errors.New("root broker accepts only strict signed mutation intents")
	}
	if configDigest == "" {
		return out, errors.New("node configuration digest is unavailable")
	}
	material, err := wsproto.CommandSigningMaterialForPlanRelaunch(command)
	if err != nil {
		return out, errors.New("plan relaunch signing material is unavailable")
	}
	signingDigest := sha256Hex(material)
	public, err := readPinnedPlanBrokerPublicKeyAt(paths.PublicKey, paths)
	if err != nil {
		return out, errors.New("root broker acknowledgement key is unavailable")
	}
	stateBody, stateInfo, err := readOwnedStopBoundedAt(cfg.CommandStatePath, 32<<20, stopPaths)
	if err != nil || stateInfo == nil || rejectDuplicateJSONKeys(stateBody) != nil {
		return out, errors.New("node state envelope is unavailable")
	}
	var envelope commandStateEnvelope
	if decodeStrictCanonicalState(stateBody, &envelope) != nil || envelope.Version != commandStateVersion || envelope.Checksum == "" || envelope.State.Pending == nil || envelope.State.Fences == nil || envelope.State.PlanRelaunchOperations == nil || envelope.State.JournalSequence == 0 || envelope.State.RecoveryEpoch != command.Args["recovery_epoch"] {
		return out, errors.New("node durable plan relaunch state is incomplete")
	}
	encodedState, err := json.Marshal(envelope.State)
	if err != nil || sha256Hex(encodedState) != envelope.Checksum || verifyOwnedStopJournalReadOnly(cfg, envelope.State, envelope.Checksum, stopPaths) != nil {
		return out, errors.New("node state checksum or full journal does not match")
	}
	if _, err := os.Lstat(cfg.CommandStatePath + ".recovery"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return out, errors.New("node recovery marker is present or unreadable")
	}
	pending, ok := envelope.State.Pending[command.ID]
	if !ok || pending.Command != command.Command || pending.CommandID != command.ID || pending.IdempotencyKey != command.IdempotencyKey || pending.Token != int64FromArg(command.Args["fencing_token"]) || !bytes.Equal(pending.OriginalEnvelope, wire) || pending.PlanRelaunchSigningMaterialSHA256 != signingDigest || !bytes.Equal(pending.PinnedPlanBrokerPublicKey, public) || pending.StopRecoveryEpoch != command.Args["recovery_epoch"] {
		return out, errors.New("node state lacks the exact durable original plan relaunch intent")
	}
	accelerator := fmt.Sprint(command.Args["accelerator_id"])
	fence := int64FromArg(command.Args["fencing_token"])
	targetID := fmt.Sprint(command.Args["target_id"])
	targetAllowed := false
	for _, server := range cfg.LlamaCPP.Servers {
		if targetID == cfg.NodeID+"-"+server.ID && server.ID != "" {
			targetAllowed = true
			break
		}
	}
	if !targetAllowed {
		return out, errors.New("signed plan relaunch target is not a fixed local server")
	}
	if envelope.State.Fences[ownedStopFenceKey(accelerator)] != fence || envelope.State.Fences[checkpointPlanRelaunchFenceKey(accelerator)] != fence {
		return out, errors.New("node stop and relaunch fences do not match")
	}
	operation := envelope.State.PlanRelaunchOperations[accelerator]
	step, _ := checkpointPlanRelaunchStepForCommand(command.Command)
	operationStep, exists := operation.Steps[step]
	if !exists || operation.OperationID != command.Args["operation_id"] || operation.Fence != fence || operation.RecoveryEpoch != command.Args["recovery_epoch"] || operationStep.Status != "pending" || operationStep.CommandID != command.ID || operationStep.EnvelopeSHA256 != sha256Hex(wire) || operationStep.SigningMaterialSHA256 != signingDigest {
		return out, errors.New("node operation-step journal does not bind the original plan request")
	}
	for id, other := range envelope.State.Pending {
		if id == command.ID || (other.Command != "llm_displacement_stop" && !checkpointPlanRelaunchIsCommand(other.Command)) {
			continue
		}
		var otherManifest pendingOperationManifest
		if rejectDuplicateJSONKeys([]byte(other.ManifestJSON)) != nil || json.Unmarshal([]byte(other.ManifestJSON), &otherManifest) != nil {
			return out, errors.New("another privileged lifecycle intent has a malformed pending manifest")
		}
		if fmt.Sprint(otherManifest.Args["accelerator_id"]) == accelerator {
			return out, errors.New("another stop or plan lifecycle intent still holds this accelerator")
		}
	}
	normalized := make(map[string]any, len(command.Args)+1)
	for key, value := range command.Args {
		normalized[key] = value
	}
	normalized["resource"] = "plan-relaunch:" + accelerator
	fingerprint := wsproto.ResidencyCommandFingerprint(cfg.NodeID, command.Command, command.IdempotencyKey, normalized)
	var manifest pendingOperationManifest
	manifestRaw := []byte(pending.ManifestJSON)
	if rejectDuplicateJSONKeys(manifestRaw) != nil {
		return out, errors.New("node pending manifest is malformed")
	}
	manifestDecoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	manifestDecoder.DisallowUnknownFields()
	if manifestDecoder.Decode(&manifest) != nil {
		return out, errors.New("node pending manifest is malformed")
	}
	canonicalManifest, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonicalManifest, manifestRaw) || manifest.Action != command.Command || manifest.NodeID != cfg.NodeID || manifest.CommandID != command.ID || manifest.IdempotencyKey != command.IdempotencyKey || manifest.Fingerprint != fingerprint || pending.Fingerprint != fingerprint || manifest.TargetKind != "llamacpp" || manifest.TargetID != command.Args["target_id"] || manifest.Model != "plan-relaunch:"+accelerator || manifest.FencingToken != fence || !reflect.DeepEqual(manifest.Args, normalized) || envelope.State.CommandFingerprints["id:"+command.ID] != fingerprint || envelope.State.CommandFingerprints[command.IdempotencyKey] != fingerprint {
		return out, errors.New("node pending manifest or fingerprints do not bind the exact typed command")
	}
	priorID := fmt.Sprint(command.Args["prior_command_id"])
	stopOp := envelope.State.OwnedStopOperations[accelerator]
	priorStepID := "victim_stop"
	if command.Command == checkpointPlanRelaunchVictimCommand {
		priorStepID = "urgent_stop"
	}
	stopStep, ok := stopOp.Steps[priorStepID]
	if !ok || !stopOp.UsedOperationIDs[fmt.Sprint(command.Args["operation_id"])] || stopOp.OperationID != command.Args["operation_id"] || stopOp.AcceleratorID != accelerator || stopOp.Fence != fence || stopOp.RecoveryEpoch != command.Args["recovery_epoch"] || stopStep.Status != "acknowledged" || stopStep.CommandID != priorID || stopStep.IdempotencyKey != command.Args["prior_idempotency_key"] || stopStep.ReceiptSHA256 != command.Args["prior_receipt_sha256"] {
		return out, errors.New("plan relaunch predecessor is not the exact acknowledged root stop step")
	}
	stopKey, err := readPinnedRootStopPublicKeyAt(stopPaths.PublicKey, stopPaths)
	if err != nil {
		return out, errors.New("root stop acknowledgement key is unavailable")
	}
	priorPath := filepath.Join(stopPaths.ReceiptDir, ownedStopReceiptFilename(priorID))
	priorDirInfo, dirErr := os.Lstat(stopPaths.ReceiptDir)
	priorDirStat, dirOK := infoSys(priorDirInfo)
	if dirErr != nil || !dirOK || !priorDirInfo.IsDir() || priorDirInfo.Mode()&os.ModeSymlink != 0 || priorDirStat.Uid != 0 || priorDirStat.Gid != stopPaths.NodeGID || priorDirInfo.Mode().Perm() != 0o750 || checkpointOwnedStopPathChainAt(priorPath, stopPaths, true) != nil {
		return out, errors.New("root stop receipt directory is unsafe")
	}
	priorWire, priorInfo, err := readPlanBrokerFile(priorPath, 16<<10, 0o640)
	priorStat, priorOK := infoSys(priorInfo)
	if err == nil && (!priorOK || priorStat.Uid != 0 || priorStat.Gid != stopPaths.NodeGID) {
		err = errors.New("root stop receipt ownership is invalid")
	}
	var priorReceipt ownedStopReceipt
	priorDecoder := json.NewDecoder(bytes.NewReader(priorWire))
	priorDecoder.DisallowUnknownFields()
	if err != nil || sha256Hex(priorWire) != stopStep.ReceiptSHA256 || stopStep.EnvelopeSHA256 == "" || rejectDuplicateJSONKeys(priorWire) != nil || priorDecoder.Decode(&priorReceipt) != nil || verifyOwnedStopReceiptSignature(priorReceipt, ed25519.PublicKey(stopKey)) != nil {
		return out, errors.New("root stop predecessor receipt does not verify against the exact prior intent")
	}
	canonicalPriorReceipt, err := json.Marshal(priorReceipt)
	if err != nil || !bytes.Equal(canonicalPriorReceipt, priorWire) || priorReceipt.OriginalEnvelopeSHA256 != stopStep.EnvelopeSHA256 {
		return out, errors.New("root stop receipt is not canonical or differs from its journaled original digest")
	}
	if priorReceipt.NodeID != cfg.NodeID || priorReceipt.OperationID != command.Args["operation_id"] || priorReceipt.StepID != priorStepID || priorReceipt.CommandID != priorID || priorReceipt.IdempotencyKey != command.Args["prior_idempotency_key"] || priorReceipt.AcceleratorID != accelerator || priorReceipt.FencingToken != fence || priorReceipt.RecoveryEpoch != command.Args["recovery_epoch"] || priorReceipt.TargetID != command.Args["target_id"] || priorReceipt.WorkloadID != command.Args["workload_id"] || priorReceipt.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) {
		return out, errors.New("root stop receipt differs from the original operation identity")
	}
	if err := verifyCheckpointPlanBrokerPriorStopResult(envelope.State, paths, command, stopOp, stopStep, priorWire, ed25519.PublicKey(stopKey), cfg.CommandSigningSecret); err != nil {
		return out, err
	}
	catalogRaw, catalogInfo, err := readPlanBrokerFile(paths.Catalog, checkpointPlanCatalogMaxBytes, 0)
	if err != nil || catalogInfo == nil || checkpointPlanBrokerTrustedDirectory(filepath.Dir(paths.Catalog)) != nil {
		return out, errors.New("approved root catalog is unavailable")
	}
	_, entries, err := decodeCheckpointPlanCatalog(catalogRaw, paths)
	if err != nil {
		return out, err
	}
	selected, ok := entries[fmt.Sprint(command.Args["catalog_id"])]
	if !ok || selected.WorkloadID != command.Args["workload_id"] || selected.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) {
		return out, errors.New("selected catalog entry is not independently approved")
	}
	if command.Command == checkpointPlanRelaunchUrgentCommand {
		victim, ok := entries[fmt.Sprint(command.Args["linked_catalog_id"])]
		if !ok || victim.CatalogID == selected.CatalogID || victim.WorkloadID != command.Args["workload_id"] || victim.WorkloadRevision != int64FromArg(command.Args["workload_revision"]) {
			return out, errors.New("linked victim catalog is not independently approved")
		}
		victimRaw, decodeErr := base64.StdEncoding.DecodeString(victim.PlanBase64)
		var victimPlan CheckpointLaunchPlan
		if decodeErr != nil || json.Unmarshal(victimRaw, &victimPlan) != nil || victimPlan.Alias != priorReceipt.ModelAlias {
			return out, errors.New("linked victim catalog does not match the stopped victim alias")
		}
	}
	stopped, err := queryCheckpointPlanBrokerStoppedState(ctx, paths)
	if err != nil {
		return out, err
	}
	if err := verifyCheckpointPlanBrokerStoppedObservation(stopped, paths, priorReceipt); err != nil {
		return out, err
	}
	_, gid, err := checkpointOwnedStopPrincipal(stopPaths)
	if err != nil {
		return out, errors.New("fixed node principal is unavailable")
	}
	return verifiedPlanBrokerIntent{Config: cfg, Command: command, Pending: pending, Stopped: stopped, PriorReceipt: priorReceipt, PriorReceiptSHA256: sha256Hex(priorWire), CatalogEntries: entries, CatalogSHA256: sha256Hex(catalogRaw), CatalogInfo: catalogInfo, RootPublicKey: append([]byte(nil), public...), SigningDigest: signingDigest, NodeGID: gid}, nil
}

func reconcileCheckpointPlanBrokerQuery(ctx context.Context, paths checkpointPlanBrokerPaths, wire []byte, query wsproto.CommandPayload) (checkpointPlanBrokerResponse, error) {
	stopPaths := checkpointPlanBrokerOwnedStopPaths(paths)
	cfg, _, err := loadOwnedStopNodeConfigAt(stopPaths)
	if ctx == nil || ctx.Err() != nil || cfg == nil || wsproto.ValidatePlanRelaunchCommandArgs(query.Command, query.Args) != nil || !wsproto.VerifyCommand(query, []byte(cfg.CommandSigningSecret)) {
		return checkpointPlanBrokerResponse{}, errors.New("signed lifecycle query is invalid")
	}
	if err != nil || query.NodeID != cfg.NodeID || validateCheckpointPlanRelaunchCommandTime(query, time.Now().UTC()) != nil {
		return checkpointPlanBrokerResponse{}, errors.New("lifecycle query node or validity window is invalid")
	}
	canonical, err := wsproto.CanonicalCommandEnvelope(query)
	if err != nil || !bytes.Equal(canonical, wire) {
		return checkpointPlanBrokerResponse{}, errors.New("lifecycle query is not canonical")
	}
	stateBody, _, err := readOwnedStopBoundedAt(cfg.CommandStatePath, 32<<20, stopPaths)
	if err != nil {
		return checkpointPlanBrokerResponse{}, errors.New("node lifecycle operation journal is unavailable")
	}
	var envelope commandStateEnvelope
	if decodeStrictCanonicalState(stateBody, &envelope) != nil || envelope.Version != commandStateVersion || envelope.State.RecoveryEpoch != query.Args["recovery_epoch"] || envelope.State.PlanRelaunchOperations == nil {
		return checkpointPlanBrokerResponse{}, errors.New("node lifecycle operation state is invalid")
	}
	stateBytes, err := json.Marshal(envelope.State)
	if err != nil || sha256Hex(stateBytes) != envelope.Checksum || verifyOwnedStopJournalReadOnly(cfg, envelope.State, envelope.Checksum, stopPaths) != nil {
		return checkpointPlanBrokerResponse{}, errors.New("node lifecycle journal or checksum does not match")
	}
	accelerator := fmt.Sprint(query.Args["accelerator_id"])
	stepID := fmt.Sprint(query.Args["query_step"])
	operation := envelope.State.PlanRelaunchOperations[accelerator]
	step, exists := operation.Steps[stepID]
	if !exists || operation.OperationID != query.Args["operation_id"] || operation.Fence != int64FromArg(query.Args["fencing_token"]) || operation.RecoveryEpoch != query.Args["recovery_epoch"] || step.CommandID != query.Args["original_command_id"] || step.IdempotencyKey != query.Args["original_idempotency_key"] || step.EnvelopeSHA256 != query.Args["original_envelope_sha256"] || sha256Hex(step.OriginalEnvelope) != step.EnvelopeSHA256 || !bytes.Equal(step.PinnedRootPublicKey, mustPlanBrokerPublicKey(paths)) {
		return checkpointPlanBrokerResponse{}, errors.New("lifecycle query does not match the exact node-persisted original")
	}
	var original wsproto.CommandPayload
	if rejectDuplicateJSONKeys(step.OriginalEnvelope) != nil || json.Unmarshal(step.OriginalEnvelope, &original) != nil || !wsproto.VerifyCommand(original, []byte(cfg.CommandSigningSecret)) || wsproto.ValidatePlanRelaunchCommandArgs(original.Command, original.Args) != nil || original.ID != step.CommandID || original.IdempotencyKey != step.IdempotencyKey {
		return checkpointPlanBrokerResponse{}, errors.New("persisted original lifecycle envelope fails its signature or type")
	}
	canonicalOriginal, err := wsproto.CanonicalCommandEnvelope(original)
	if err != nil || !bytes.Equal(canonicalOriginal, step.OriginalEnvelope) || original.NodeID != cfg.NodeID || original.Command == checkpointPlanRelaunchQueryCommand || original.Args["operation_id"] != operation.OperationID || original.Args["accelerator_id"] != accelerator || int64FromArg(original.Args["fencing_token"]) != operation.Fence {
		return checkpointPlanBrokerResponse{}, errors.New("persisted original lifecycle envelope is not canonically linked")
	}
	originalSigningDigest, originalSigningErr := planRelaunchSigningMaterialDigest(original)
	if originalSigningErr != nil || originalSigningDigest != step.SigningMaterialSHA256 {
		return checkpointPlanBrokerResponse{}, errors.New("persisted original signing-material digest differs")
	}
	if envelope.State.Fences[ownedStopFenceKey(accelerator)] != operation.Fence || envelope.State.Fences[checkpointPlanRelaunchFenceKey(accelerator)] != operation.Fence {
		return checkpointPlanBrokerResponse{}, errors.New("query no longer matches the shared accelerator operation fence")
	}
	if step.Status == "pending" {
		pending, exists := envelope.State.Pending[step.CommandID]
		if !exists || !bytes.Equal(pending.OriginalEnvelope, step.OriginalEnvelope) || pending.PlanRelaunchSigningMaterialSHA256 != step.SigningMaterialSHA256 || !bytes.Equal(pending.PinnedPlanBrokerPublicKey, step.PinnedRootPublicKey) {
			return checkpointPlanBrokerResponse{}, errors.New("query pending step differs from the exact durable command intent")
		}
	} else if step.Status != "acknowledged" || step.ReceiptSHA256 != sha256Hex(step.Receipt) || len(step.Receipt) == 0 {
		return checkpointPlanBrokerResponse{}, errors.New("query operation step is neither pending nor acknowledged")
	}
	for _, key := range []string{"operation_id", "target_id", "accelerator_id", "workload_id", "workload_revision", "recovery_epoch", "fencing_token", "prior_command_id", "prior_idempotency_key", "prior_receipt_sha256", "catalog_id"} {
		if fmt.Sprint(query.Args[key]) != fmt.Sprint(original.Args[key]) {
			return checkpointPlanBrokerResponse{}, errors.New("lifecycle query does not preserve original signed fields")
		}
	}
	if operation.TargetID != original.Args["target_id"] || operation.WorkloadID != original.Args["workload_id"] || operation.WorkloadRevision != int64FromArg(original.Args["workload_revision"]) || operation.RecoveryEpoch != original.Args["recovery_epoch"] || ((stepID == "urgent_load") != (original.Command == checkpointPlanRelaunchUrgentCommand)) {
		return checkpointPlanBrokerResponse{}, errors.New("query operation fields do not match the signed original")
	}
	if original.Command == checkpointPlanRelaunchUrgentCommand && query.Args["linked_catalog_id"] != original.Args["linked_catalog_id"] {
		return checkpointPlanBrokerResponse{}, errors.New("lifecycle query changed the linked victim catalog")
	}
	journal, err := loadCheckpointPlanBrokerJournal(paths.Journal, paths)
	if err != nil {
		return checkpointPlanBrokerResponse{}, errors.New("root lifecycle journal is not available for reconciliation")
	}
	entry := journal.Operations[operation.OperationID]
	stepRecord, exists := entry.Steps[stepID]
	if !exists || entry.Operation.AcceleratorID != accelerator || entry.Operation.Fence != operation.Fence || stepRecord.CommandID != original.ID || stepRecord.EnvelopeSHA256 != step.EnvelopeSHA256 {
		return checkpointPlanBrokerResponse{}, errors.New("root lifecycle journal does not bind the exact node intent")
	}
	if stepRecord.Status != "acknowledged" || len(stepRecord.Receipt) == 0 {
		return reconcileCheckpointPlanBrokerPending(ctx, paths, cfg, envelope.State, operation, entry, stepID, step, stepRecord)
	}
	rootPublic, err := readPlanBrokerPublicKeyAt(paths.PublicKey, paths)
	if err != nil {
		return checkpointPlanBrokerResponse{}, err
	}
	if _, err := verifyCheckpointPlanRelaunchReceipt(stepRecord.Receipt, rootPublic, step.OriginalEnvelope, cfg.CommandSigningSecret); err != nil || sha256Hex(stepRecord.Receipt) != stepRecord.ReceiptSHA256 {
		return checkpointPlanBrokerResponse{}, errors.New("root lifecycle receipt is invalid")
	}
	return checkpointPlanBrokerResponse{Receipt: append([]byte(nil), stepRecord.Receipt...)}, nil
}

func reconcileCheckpointPlanBrokerPending(ctx context.Context, paths checkpointPlanBrokerPaths, cfg *Config, state commandStatePayload, operation checkpointPlanRelaunchOperation, entry checkpointPlanBrokerOperation, stepID string, nodeStep checkpointPlanRelaunchStep, rootStep checkpointPlanRelaunchStep) (checkpointPlanBrokerResponse, error) {
	if cfg == nil || state.RecoveryEpoch != operation.RecoveryEpoch || state.Fences[ownedStopFenceKey(operation.AcceleratorID)] != operation.Fence || state.Fences[checkpointPlanRelaunchFenceKey(operation.AcceleratorID)] != operation.Fence || nodeStep.Status != "pending" || !bytes.Equal(nodeStep.OriginalEnvelope, rootStep.OriginalEnvelope) || rootStep.Status != "pending" {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	var original wsproto.CommandPayload
	if rejectDuplicateJSONKeys(nodeStep.OriginalEnvelope) != nil || json.Unmarshal(nodeStep.OriginalEnvelope, &original) != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	acceptedAt, acceptedErr := time.Parse(time.RFC3339Nano, rootStep.AcceptedAt)
	canonicalOriginal, canonicalErr := wsproto.CanonicalCommandEnvelope(original)
	if !wsproto.VerifyCommand(original, []byte(cfg.CommandSigningSecret)) || canonicalErr != nil || !bytes.Equal(canonicalOriginal, nodeStep.OriginalEnvelope) || acceptedErr != nil || acceptedAt.Before(original.IssuedAt) || acceptedAt.After(original.ExpiresAt) || rootStep.AcceptedAt == "" {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	priorReceipt, priorErr := checkpointPlanBrokerColdPriorStopReceipt(paths, state, original, cfg)
	if priorErr != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	catalogRaw, _, err := readPlanBrokerFile(paths.Catalog, checkpointPlanCatalogMaxBytes, 0)
	if err != nil || sha256Hex(catalogRaw) != entry.CatalogSHA256 {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	_, catalog, err := decodeCheckpointPlanCatalog(catalogRaw, paths)
	if err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	selected, ok := catalog[fmt.Sprint(original.Args["catalog_id"])]
	if !ok || selected.PlanSHA256 != entry.PlanSHA256 {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	planRaw, err := base64.StdEncoding.DecodeString(selected.PlanBase64)
	if err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	plan, err := ParseCheckpointLaunchPlan(planRaw)
	if err != nil || plan.Version != checkpointLaunchPlanVersion2 || validateCheckpointPlanBrokerPlan(paths, plan) != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	private, public, err := loadCheckpointPlanBrokerSigningKey(paths)
	if err != nil || !bytes.Equal(public, nodeStep.PinnedRootPublicKey) {
		return checkpointPlanBrokerResponse{}, errors.New("root plan broker key pin changed during recovery")
	}
	receiptPath := filepath.Join(paths.ReceiptDir, ownedStopReceiptFilename(original.ID))
	var receiptRaw []byte
	var binding CheckpointManagedBinding
	if _, statErr := os.Lstat(receiptPath); statErr == nil {
		receiptRaw, _, err = readPlanBrokerFile(receiptPath, 32<<10, 0o640)
		var existingReceipt checkpointPlanRelaunchReceipt
		if err == nil {
			existingReceipt, err = verifyCheckpointPlanRelaunchReceipt(receiptRaw, public, nodeStep.OriginalEnvelope, cfg.CommandSigningSecret)
		}
		if err != nil || existingReceipt.Step != stepID || existingReceipt.OperationID != operation.OperationID || existingReceipt.CatalogID != selected.CatalogID || existingReceipt.CatalogSHA256 != entry.CatalogSHA256 || existingReceipt.PlanSHA256 != selected.PlanSHA256 || existingReceipt.AcceptedAt != rootStep.AcceptedAt || existingReceipt.PriorInvocationID != entry.PriorInvocation {
			return checkpointPlanBrokerResponse{}, errors.New("existing root receipt cannot be joined to the exact pending command")
		}
		binding.Association.Invocation = existingReceipt.InvocationID
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return checkpointPlanBrokerResponse{}, errors.New("root receipt path could not be inspected")
	} else {
		if entry.Stage != stepID+"_prepared" && entry.Stage != stepID+"_published" && entry.Stage != stepID+"_start_requested" && entry.Stage != stepID+"_start_accepted" {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		active, activeInfo, readErr := readPlanBrokerFile(paths.ActivePlan, checkpointLaunchPlanMaxBytes, 0)
		if readErr != nil {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		activeDigest := sha256Hex(active)
		unit, unitErr := checkpointPlanBrokerUnitState(ctx, paths)
		var stopped *checkpointPlanBrokerStoppedState
		if unitErr != nil || unit.MainPID == 0 {
			observed, stoppedErr := queryCheckpointPlanBrokerStoppedState(ctx, paths)
			if stoppedErr != nil || verifyCheckpointPlanBrokerStoppedObservation(observed, paths, priorReceipt) != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			stopped = &observed
		}
		if activeDigest == entry.PriorPlanSHA256 && entry.Stage == stepID+"_prepared" {
			if stopped == nil || checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, priorReceipt) != nil || entry.PriorInvocation != priorReceipt.InvocationID {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if err := publishCheckpointPlanBrokerPlan(ctx, paths, paths.ActivePlan, active, activeInfo, planRaw, entry.PriorPlanSHA256, priorReceipt); err != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if checkpointPlanBrokerFixtureFault(paths, "plan_published") {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			activeDigest = selected.PlanSHA256
		} else if activeDigest != selected.PlanSHA256 {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		if entry.Stage == stepID+"_prepared" {
			entry.Stage = stepID + "_published"
			if err := persistCheckpointPlanBrokerRecoveryEntry(paths, operation.OperationID, stepID, rootStep, entry); err != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if checkpointPlanBrokerFixtureFault(paths, "published_durable") {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
		}
		if stopped != nil {
			if !checkpointPlanRelaunchMayIssueFirstStart(stepID, entry.Stage) {
				// Once start_requested is durable, absence is ambiguous: the old
				// broker may have died before, during, or after systemctl start.
				// Never turn that uncertainty into a duplicate launch.
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if entry.PriorInvocation != priorReceipt.InvocationID || checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, priorReceipt) != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			entry.Stage = stepID + "_start_requested"
			if err := persistCheckpointPlanBrokerRecoveryEntry(paths, operation.OperationID, stepID, rootStep, entry); err != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if checkpointPlanBrokerFixtureFault(paths, "start_requested_durable") {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if verifyCheckpointPlanBrokerStartState(ctx, paths, selected.PlanSHA256, priorReceipt) != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if _, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "start", checkpointPlanBrokerUnitName(paths)); err != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if checkpointPlanBrokerFixtureFault(paths, "systemd_start_returned") {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			entry.Stage = stepID + "_start_accepted"
			if err := persistCheckpointPlanBrokerRecoveryEntry(paths, operation.OperationID, stepID, rootStep, entry); err != nil {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if checkpointPlanBrokerFixtureFault(paths, "start_accepted_durable") {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
		} else {
			if unitErr != nil || !checkpointPlanRelaunchMayJoinStartedProcess(stepID, entry.Stage) || unit.MainPID <= 1 || unit.Active != "active" || unit.Sub != "running" {
				return checkpointPlanBrokerResponse{Pending: true}, nil
			}
			if entry.Stage == stepID+"_start_requested" {
				entry.Stage = stepID + "_start_accepted"
				if err := persistCheckpointPlanBrokerRecoveryEntry(paths, operation.OperationID, stepID, rootStep, entry); err != nil {
					return checkpointPlanBrokerResponse{Pending: true}, nil
				}
				if checkpointPlanBrokerFixtureFault(paths, "start_accepted_durable") {
					return checkpointPlanBrokerResponse{Pending: true}, nil
				}
			}
		}
		var bindErr error
		binding, bindErr = awaitCheckpointPlanBrokerBinding(ctx, paths, plan, selected.PlanSHA256, entry.PriorInvocation)
		if bindErr != nil {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		if checkpointPlanBrokerFixtureFault(paths, "binding_observed") {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		receipt := checkpointPlanRelaunchReceipt{Version: 1, NodeID: original.NodeID, OperationID: operation.OperationID, Step: stepID, CommandID: original.ID, IdempotencyKey: original.IdempotencyKey, OriginalEnvelopeSHA256: sha256Hex(nodeStep.OriginalEnvelope), SigningMaterialSHA256: nodeStep.SigningMaterialSHA256, RecoveryEpoch: original.Args["recovery_epoch"].(string), AcceleratorID: original.Args["accelerator_id"].(string), FencingToken: int64FromArg(original.Args["fencing_token"]), TargetID: original.Args["target_id"].(string), WorkloadID: original.Args["workload_id"].(string), WorkloadRevision: int64FromArg(original.Args["workload_revision"]), CatalogID: selected.CatalogID, CatalogSHA256: entry.CatalogSHA256, PlanSHA256: selected.PlanSHA256, PriorReceiptSHA256: original.Args["prior_receipt_sha256"].(string), PriorInvocationID: entry.PriorInvocation, AcceptedAt: rootStep.AcceptedAt, InvocationID: binding.Association.Invocation, MainPID: binding.Association.Identity.PID, CurrentIncarnation: binding.CurrentIncarnation, CustodyBindingSHA256: binding.CustodyBindingSHA256, Alias: binding.Alias, SignedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if stepID == "urgent_load" {
			receipt.LinkedCatalogID = operation.VictimCatalogID
		}
		unsigned, _ := json.Marshal(receipt)
		receipt.Signature = hex.EncodeToString(ed25519.Sign(private, checkpointPlanRelaunchSigningMaterial(unsigned)))
		receiptRaw, err = json.Marshal(receipt)
		if err != nil {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		if _, verifyErr := verifyCheckpointPlanRelaunchReceipt(receiptRaw, public, nodeStep.OriginalEnvelope, cfg.CommandSigningSecret); verifyErr != nil {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		_, gid, principalErr := checkpointOwnedStopPrincipal(checkpointPlanBrokerOwnedStopPaths(paths))
		if principalErr != nil || writeCheckpointPlanBrokerReceipt(paths, receiptRaw, gid) != nil {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
		if checkpointPlanBrokerFixtureFault(paths, "receipt_durable") {
			return checkpointPlanBrokerResponse{Pending: true}, nil
		}
	}
	rootStep.Status = "acknowledged"
	rootStep.Receipt = append([]byte(nil), receiptRaw...)
	rootStep.ReceiptSHA256 = sha256Hex(receiptRaw)
	entry.Steps[stepID] = rootStep
	entry.Stage = stepID + "_acknowledged"
	entry.PriorInvocation = binding.Association.Invocation
	journal, err := loadCheckpointPlanBrokerJournal(paths.Journal, paths)
	if err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	journal.Operations[operation.OperationID] = entry
	if err := saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal); err != nil {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	if checkpointPlanBrokerFixtureFault(paths, "acknowledged_durable") {
		return checkpointPlanBrokerResponse{Pending: true}, nil
	}
	return checkpointPlanBrokerResponse{Receipt: receiptRaw}, nil
}

func persistCheckpointPlanBrokerRecoveryEntry(paths checkpointPlanBrokerPaths, operationID, stepID string, expected checkpointPlanRelaunchStep, entry checkpointPlanBrokerOperation) error {
	journal, err := loadCheckpointPlanBrokerJournal(paths.Journal, paths)
	if err != nil {
		return err
	}
	current, ok := journal.Operations[operationID]
	if !ok {
		return errors.New("root recovery journal operation disappeared")
	}
	step, ok := current.Steps[stepID]
	if !ok || step.Status != "pending" || step.EnvelopeSHA256 != expected.EnvelopeSHA256 || step.AcceptedAt != expected.AcceptedAt || !bytes.Equal(step.OriginalEnvelope, expected.OriginalEnvelope) {
		return errors.New("root recovery journal step changed before transition")
	}
	entry.Steps[stepID] = step
	journal.Operations[operationID] = entry
	return saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal)
}

func verifyCheckpointPlanBrokerStartState(ctx context.Context, paths checkpointPlanBrokerPaths, expectedPlan string, prior ownedStopReceipt) error {
	if ctx == nil || ctx.Err() != nil || !checkpointSHA256RE.MatchString(expectedPlan) || prior.InvocationID == "" {
		return errors.New("fixed worker start intent is incomplete")
	}
	active, _, err := readPlanBrokerFile(paths.ActivePlan, checkpointLaunchPlanMaxBytes, 0)
	if err != nil || sha256Hex(active) != expectedPlan {
		return errors.New("active plan changed before the fixed start request")
	}
	if err := checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior); err != nil {
		return errors.New("fixed worker is not freshly inactive immediately before start")
	}
	return nil
}

func mustPlanBrokerPublicKey(paths checkpointPlanBrokerPaths) []byte {
	key, _ := readPinnedPlanBrokerPublicKeyAt(paths.PublicKey, paths)
	return key
}

func loadCheckpointPlanBrokerJournal(path string, paths checkpointPlanBrokerPaths) (checkpointPlanBrokerJournal, error) {
	journal := checkpointPlanBrokerJournal{Version: checkpointPlanBrokerJournalVersion, Operations: make(map[string]checkpointPlanBrokerOperation)}
	if path != paths.Journal || (path != checkpointPlanBrokerJournalPath && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/private/operations.json")) || checkpointPlanBrokerRootDir(filepath.Dir(path), 0o700) != nil {
		return journal, errors.New("root plan broker journal parent is unsafe")
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return journal, os.ErrNotExist
	} else if err != nil {
		return journal, errors.New("root plan broker journal is unavailable")
	}
	raw, _, err := readPlanBrokerFile(path, 32<<20, 0o600)
	if err != nil {
		return journal, errors.New("root plan broker journal is unavailable")
	}
	if rejectDuplicateJSONKeys(raw) != nil {
		return journal, errors.New("root plan broker journal has duplicate fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || journal.Version != checkpointPlanBrokerJournalVersion || journal.Operations == nil || journal.Checksum == "" {
		return journal, errors.New("root plan broker journal schema is invalid")
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, raw) {
		return journal, errors.New("root plan broker journal is not canonical")
	}
	checksum := journal.Checksum
	journal.Checksum = ""
	unsigned, _ := json.Marshal(journal)
	if sha256Hex(unsigned) != checksum {
		return journal, errors.New("root plan broker journal checksum differs")
	}
	journal.Checksum = checksum
	if err := validateCheckpointPlanBrokerJournal(journal); err != nil {
		return journal, err
	}
	return journal, nil
}

func saveCheckpointPlanBrokerJournal(path string, paths checkpointPlanBrokerPaths, journal *checkpointPlanBrokerJournal) error {
	if journal == nil || path != paths.Journal || (path != checkpointPlanBrokerJournalPath && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/private/operations.json")) {
		return errors.New("root plan broker journal target is not fixed")
	}
	if err := checkpointPlanBrokerRootDir(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if journal.Sequence == ^uint64(0) {
		return errors.New("root plan broker journal sequence is exhausted")
	}
	journal.Version = checkpointPlanBrokerJournalVersion
	journal.Sequence++
	journal.Checksum = ""
	if err := validateCheckpointPlanBrokerJournal(*journal); err != nil {
		return err
	}
	unsigned, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	journal.Checksum = sha256Hex(unsigned)
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return checkpointPlanBrokerWriteAtomic(path, raw, 0o600)
}

func validateCheckpointPlanBrokerJournal(journal checkpointPlanBrokerJournal) error {
	if journal.Version != checkpointPlanBrokerJournalVersion || journal.Sequence == 0 || journal.Operations == nil || len(journal.Operations) > 256 {
		return errors.New("root plan broker journal exceeds its fixed schema bounds")
	}
	for id, operation := range journal.Operations {
		if !canonicalPlanCatalogToken(id) || operation.Operation.OperationID != id || !canonicalPlanCatalogToken(operation.Operation.AcceleratorID) || operation.Operation.Fence <= 0 || len(operation.Steps) == 0 || len(operation.Steps) > 2 || !checkpointSHA256RE.MatchString(operation.CatalogSHA256) || !checkpointSHA256RE.MatchString(operation.PlanSHA256) || !checkpointSHA256RE.MatchString(operation.PriorPlanSHA256) || operation.PriorInvocation == "" {
			return errors.New("root plan broker journal operation identity is invalid")
		}
		switch operation.Stage {
		case "urgent_load_prepared", "urgent_load_published", "urgent_load_start_requested", "urgent_load_start_accepted", "urgent_load_acknowledged", "victim_reload_prepared", "victim_reload_published", "victim_reload_start_requested", "victim_reload_start_accepted", "victim_reload_acknowledged":
		default:
			return errors.New("root plan broker journal stage is invalid")
		}
		for stepID, step := range operation.Steps {
			if stepID != "urgent_load" && stepID != "victim_reload" || step.CommandID == "" || step.IdempotencyKey == "" || !checkpointSHA256RE.MatchString(step.EnvelopeSHA256) || len(step.OriginalEnvelope) == 0 || len(step.OriginalEnvelope) > checkpointPlanRelaunchMaxFrame || !checkpointSHA256RE.MatchString(step.SigningMaterialSHA256) || (step.Status != "pending" && step.Status != "acknowledged") {
				return errors.New("root plan broker journal step identity is invalid")
			}
			var command wsproto.CommandPayload
			if rejectDuplicateJSONKeys(step.OriginalEnvelope) != nil || json.Unmarshal(step.OriginalEnvelope, &command) != nil || sha256Hex(step.OriginalEnvelope) != step.EnvelopeSHA256 || command.ID != step.CommandID || command.IdempotencyKey != step.IdempotencyKey || (stepID == "urgent_load" && command.Command != checkpointPlanRelaunchUrgentCommand) || (stepID == "victim_reload" && command.Command != checkpointPlanRelaunchVictimCommand) {
				return errors.New("root plan broker journal original envelope is inconsistent")
			}
			if step.AcceptedAt != "" {
				acceptedAt, acceptedErr := time.Parse(time.RFC3339Nano, step.AcceptedAt)
				if acceptedErr != nil || acceptedAt.Before(command.IssuedAt) || acceptedAt.After(command.ExpiresAt) {
					return errors.New("root plan broker journal acceptance time is invalid")
				}
			}
			if step.Status == "acknowledged" && (len(step.Receipt) == 0 || len(step.Receipt) > 32<<10 || !checkpointSHA256RE.MatchString(step.ReceiptSHA256) || sha256Hex(step.Receipt) != step.ReceiptSHA256) {
				return errors.New("root plan broker journal acknowledgement is incomplete")
			}
			if step.Status == "pending" && (len(step.Receipt) != 0 || step.ReceiptSHA256 != "") {
				return errors.New("pending root plan broker step has terminal evidence")
			}
		}
	}
	return nil
}

func publishCheckpointPlanBrokerPlan(ctx context.Context, paths checkpointPlanBrokerPaths, path string, oldRaw []byte, oldInfo os.FileInfo, next []byte, oldDigest string, prior ownedStopReceipt) error {
	if path != paths.ActivePlan || (!paths.privateFixture && path != checkpointFixedPlanPath) || oldInfo == nil || oldDigest != sha256Hex(oldRaw) || len(next) == 0 || len(next) > checkpointLaunchPlanMaxBytes {
		return errors.New("fixed plan CAS precondition is invalid")
	}
	if err := checkpointPlanBrokerTrustedDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	current, info, err := readPlanBrokerFile(path, checkpointLaunchPlanMaxBytes, 0)
	if err != nil || !os.SameFile(oldInfo, info) || sha256Hex(current) != oldDigest || !bytes.Equal(current, oldRaw) || oldInfo.Mode().Perm()&0o022 != 0 || oldInfo.Mode().Perm()&0o400 == 0 {
		return errors.New("fixed active plan changed before publication")
	}
	if err := checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior); err != nil {
		return errors.New("fixed worker is not inactive immediately before publication")
	}
	if err := checkpointPlanBrokerWriteAtomic(path, next, oldInfo.Mode().Perm()); err != nil {
		return err
	}
	return nil
}

func awaitCheckpointPlanBrokerBinding(ctx context.Context, paths checkpointPlanBrokerPaths, plan CheckpointLaunchPlan, digest, priorInvocation string) (CheckpointManagedBinding, error) {
	if ctx == nil || ctx.Err() != nil || digest == "" || priorInvocation == "" {
		return CheckpointManagedBinding{}, errors.New("plan broker readiness request is incomplete")
	}
	observe := ObserveCheckpointManagedLocalBinding
	if paths.privateFixture {
		if !checkpointPlanBrokerPrivateFixturePathSet(paths) || paths.bindingObserver == nil {
			return CheckpointManagedBinding{}, errors.New("private plan broker fixture observer is unavailable")
		}
		observe = func(callCtx context.Context) (CheckpointManagedBinding, error) {
			return paths.bindingObserver(callCtx, plan, digest, priorInvocation)
		}
	} else if paths.bindingObserver != nil {
		return CheckpointManagedBinding{}, errors.New("production plan broker cannot replace its fixed readiness observer")
	}
	if plan.Placement == nil {
		return CheckpointManagedBinding{}, errors.New("plan broker requires a pinned physical placement")
	}
	deadline := time.NewTimer(checkpointPlanBrokerMaxTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	var first CheckpointManagedBinding
	haveFirst := false
	for {
		binding, err := observe(ctx)
		validPlacement := binding.Placement.Backend == plan.Placement.Backend && binding.Placement.PhysicalIdentity == plan.Placement.PhysicalIdentity && binding.Placement.RuntimeDeviceToken == plan.Placement.RuntimeDeviceToken && binding.Placement.RuntimeVersion == plan.Placement.RuntimeVersion
		if err == nil && validPlacement && binding.PlanSHA256 == digest && binding.Alias == plan.Alias && binding.Association.Identity.ServiceUnit == checkpointPlanBrokerUnitName(paths) && binding.Association.Identity.PID > 1 && binding.Association.Invocation != "" && binding.Association.Invocation != priorInvocation && binding.Association.ControlGroup != "" && binding.CurrentIncarnation != "" && binding.CustodyBindingSHA256 != "" {
			if !haveFirst {
				first, haveFirst = binding, true
			} else if binding.Association.Identity.PID == first.Association.Identity.PID && binding.Association.Invocation == first.Association.Invocation && binding.CurrentIncarnation == first.CurrentIncarnation && binding.CustodyBindingSHA256 == first.CustodyBindingSHA256 && binding.Placement.PhysicalIdentity == plan.Placement.PhysicalIdentity {
				return binding, nil
			}
		}
		select {
		case <-ctx.Done():
			return CheckpointManagedBinding{}, ctx.Err()
		case <-deadline.C:
			return CheckpointManagedBinding{}, errors.New("fresh fixed worker readiness was not established")
		case <-ticker.C:
		}
	}
}

func loadCheckpointPlanBrokerSigningKey(paths checkpointPlanBrokerPaths) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	private, err := readPlanBrokerPrivateKeyAt(paths.PrivateKey, paths)
	if err != nil {
		return nil, nil, err
	}
	public, err := readPlanBrokerPublicKeyAt(paths.PublicKey, paths)
	if err != nil {
		return nil, nil, err
	}
	derived := private.Public().(ed25519.PublicKey)
	if !bytes.Equal(derived, public) {
		return nil, nil, errors.New("root plan broker keypair does not match")
	}
	return private, public, nil
}

func writeCheckpointPlanBrokerReceipt(paths checkpointPlanBrokerPaths, raw []byte, gid uint32) error {
	if paths.ReceiptDir != checkpointPlanBrokerReceiptDir && !checkpointPlanBrokerPrivateFixturePath(paths.ReceiptDir, paths, "var/public/receipts") || len(raw) == 0 || len(raw) > 32<<10 {
		return errors.New("root plan broker receipt target is invalid")
	}
	if err := checkpointPlanBrokerReceiptDirectory(paths.ReceiptDir, gid, paths); err != nil {
		return err
	}
	var receipt checkpointPlanRelaunchReceipt
	if json.Unmarshal(raw, &receipt) != nil {
		return errors.New("root plan broker receipt is malformed")
	}
	path := filepath.Join(paths.ReceiptDir, ownedStopReceiptFilename(receipt.CommandID))
	if _, err := os.Lstat(path); err == nil {
		previous, _, readErr := readPlanBrokerFile(path, 32<<10, 0o640)
		if readErr == nil && bytes.Equal(previous, raw) {
			return nil
		}
		return errors.New("root plan broker receipt path is occupied by different evidence")
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("root plan broker receipt path cannot be inspected")
	}
	temp, file, err := checkpointPlanBrokerTempPath(paths.ReceiptDir)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(temp) }()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chown(temp, 0, int(gid)); err != nil {
		return err
	}
	if err := os.Chmod(temp, 0o640); err != nil {
		return err
	}
	if err := os.Link(temp, path); err != nil {
		return err
	}
	tempInfo, tempErr := os.Lstat(temp)
	published, publishedErr := os.Lstat(path)
	if tempErr != nil || publishedErr != nil || !os.SameFile(tempInfo, published) || published.Mode().Perm() != 0o640 {
		return errors.New("root plan broker receipt publication identity changed")
	}
	return checkpointPlanBrokerSyncDir(paths.ReceiptDir)
}

func checkpointPlanBrokerReceiptDirectory(path string, gid uint32, paths checkpointPlanBrokerPaths) error {
	if path != checkpointPlanBrokerReceiptDir && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/public/receipts") {
		return errors.New("root plan broker receipt directory is not fixed")
	}
	info, err := os.Lstat(path)
	stat, ok := infoSys(info)
	if err != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != gid || info.Mode().Perm() != 0o750 {
		return errors.New("root plan broker receipt directory metadata is unsafe")
	}
	return nil
}

func readPlanBrokerPrivateKeyAt(path string, paths checkpointPlanBrokerPaths) (ed25519.PrivateKey, error) {
	if path != paths.PrivateKey || (path != checkpointPlanBrokerPrivateKeyPath && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/private/ed25519.key")) {
		return nil, errors.New("root plan broker key path is not fixed")
	}
	if err := checkpointPlanBrokerRootDir(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	stat, ok := infoSys(before)
	if err != nil || !ok || stat.Uid != 0 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm() != 0o600 || before.Size() != ed25519.PrivateKeySize*2 {
		return nil, errors.New("root plan broker private key metadata is unsafe")
	}
	body, err := io.ReadAll(io.LimitReader(f, ed25519.PrivateKeySize*2+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || len(body) != ed25519.PrivateKeySize*2 || statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || !sameCheckpointFileSnapshot(before, after) {
		return nil, errors.New("root plan broker private key changed while held")
	}
	decoded, err := hex.DecodeString(string(body))
	if err != nil || len(decoded) != ed25519.PrivateKeySize || hex.EncodeToString(decoded) != string(body) {
		return nil, errors.New("root plan broker private key encoding is invalid")
	}
	return ed25519.PrivateKey(decoded), nil
}

func readPlanBrokerPublicKeyAt(path string, paths checkpointPlanBrokerPaths) (ed25519.PublicKey, error) {
	if path != paths.PublicKey || (path != checkpointPlanBrokerPublicKeyPath && !checkpointPlanBrokerPrivateFixturePath(path, paths, "var/public/ed25519.pub")) {
		return nil, errors.New("root plan broker public key path is not fixed")
	}
	if err := checkpointPlanBrokerRootDir(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	stat, ok := infoSys(info)
	if err != nil || !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o644 || info.Size() != ed25519.PublicKeySize*2 {
		return nil, errors.New("root plan broker public key metadata is unsafe")
	}
	body, err := io.ReadAll(io.LimitReader(f, ed25519.PublicKeySize*2+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || len(body) != ed25519.PublicKeySize*2 || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathInfo) || !sameCheckpointFileSnapshot(info, after) || stat.Nlink != 1 {
		return nil, errors.New("root plan broker public key changed during held read")
	}
	decoded, err := hex.DecodeString(string(body))
	if err != nil || len(decoded) != ed25519.PublicKeySize || hex.EncodeToString(decoded) != string(body) {
		return nil, errors.New("root plan broker public key encoding is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func readPlanBrokerFile(path string, max int64, mode os.FileMode) ([]byte, os.FileInfo, error) {
	if filepath.Clean(path) != path || !filepath.IsAbs(path) || max <= 0 || max > 64<<20 {
		return nil, nil, errors.New("root plan broker file path or bound is invalid")
	}
	f, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	stat, ok := infoSys(before)
	if err != nil || !ok || stat.Uid != 0 || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || (mode != 0 && before.Mode().Perm() != mode) || (mode == 0 && before.Mode().Perm()&0o022 != 0) || before.Size() <= 0 || before.Size() > max || stat.Nlink != 1 {
		return nil, nil, errors.New("root plan broker file metadata is unsafe")
	}
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	after, statErr := f.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || int64(len(body)) != before.Size() || statErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, pathInfo) || !sameCheckpointFileSnapshot(before, after) {
		return nil, nil, errors.New("root plan broker file changed during held read")
	}
	return body, before, nil
}

func checkpointPlanBrokerRun(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || name != checkpointFixedSystemctl {
		return nil, errors.New("plan broker fixed command is unavailable")
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, checkpointFixedSystemctl, args...)
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	var output checkpointUnitOutput
	output.max = checkpointUnitMaxOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func checkpointPlanBrokerUnitState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error) {
	raw, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", checkpointPlanBrokerUnitName(paths), "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	if err != nil || len(raw) == 0 || len(raw) > checkpointUnitMaxOutput {
		return checkpointFixedUnitState{}, errors.New("fixed plan worker state is unavailable")
	}
	return parseCheckpointPlanBrokerUnitState(raw)
}

func queryCheckpointPlanBrokerStoppedState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointPlanBrokerStoppedState, error) {
	raw, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", checkpointPlanBrokerUnitName(paths), "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState", "--property=LoadState")
	if err != nil || len(raw) == 0 || len(raw) > checkpointUnitMaxOutput {
		return checkpointPlanBrokerStoppedState{}, errors.New("fixed stopped worker observation is unavailable")
	}
	return parseCheckpointPlanBrokerStoppedState(raw)
}

func parseCheckpointPlanBrokerStoppedState(raw []byte) (checkpointPlanBrokerStoppedState, error) {
	observed, err := parseCheckpointPlanBrokerStoppedObservation(raw)
	if err != nil {
		return checkpointPlanBrokerStoppedState{}, err
	}
	if observed.Load != "loaded" {
		return checkpointPlanBrokerStoppedState{}, errors.New("fixed worker is not loaded")
	}
	return observed, nil
}

func parseCheckpointPlanBrokerStoppedObservation(raw []byte) (checkpointPlanBrokerStoppedState, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' || !utf8.Valid(raw) {
		return checkpointPlanBrokerStoppedState{}, errors.New("fixed stopped worker observation is incomplete")
	}
	values := make(map[string]string, 6)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if strings.IndexFunc(line, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return checkpointPlanBrokerStoppedState{}, errors.New("fixed stopped worker observation is malformed")
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "MainPID" && key != "InvocationID" && key != "ControlGroup" && key != "ActiveState" && key != "SubState" && key != "LoadState") {
			return checkpointPlanBrokerStoppedState{}, errors.New("fixed stopped worker observation has an unexpected field")
		}
		if _, exists := values[key]; exists {
			return checkpointPlanBrokerStoppedState{}, errors.New("fixed stopped worker observation has duplicate fields")
		}
		values[key] = value
	}
	if len(values) != 6 || values["MainPID"] != "0" || values["ActiveState"] != "inactive" || (values["LoadState"] != "loaded" && values["LoadState"] != "not-found") || (values["SubState"] != "dead" && values["SubState"] != "exited") {
		return checkpointPlanBrokerStoppedState{}, errors.New("fixed worker is not a loaded inactive stopped unit")
	}
	return checkpointPlanBrokerStoppedState{MainPID: 0, Invocation: values["InvocationID"], ControlGroup: values["ControlGroup"], Active: values["ActiveState"], Sub: values["SubState"], Load: values["LoadState"]}, nil
}

func verifyCheckpointPlanBrokerStoppedObservation(observed checkpointPlanBrokerStoppedState, paths checkpointPlanBrokerPaths, prior ownedStopReceipt) error {
	return verifyCheckpointPlanBrokerStoppedObservationLoad(observed, paths, prior, true)
}

func verifyCheckpointPlanBrokerStoppedCleanupObservation(observed checkpointPlanBrokerStoppedState, paths checkpointPlanBrokerPaths, prior ownedStopReceipt) error {
	return verifyCheckpointPlanBrokerStoppedObservationLoad(observed, paths, prior, false)
}

func verifyCheckpointPlanBrokerStoppedObservationLoad(observed checkpointPlanBrokerStoppedState, paths checkpointPlanBrokerPaths, prior ownedStopReceipt, requireLoaded bool) error {
	unit := checkpointPlanBrokerUnitName(paths)
	loadAllowed := observed.Load == "loaded" || (!requireLoaded && observed.Load == "not-found")
	if observed.MainPID != 0 || observed.Active != "inactive" || (observed.Sub != "dead" && observed.Sub != "exited") || !loadAllowed || prior.WorkerPID <= 1 || prior.WorkerStartTicks == 0 || !prior.SignalSent || !prior.ReleaseTerminal || prior.InvocationID == "" || prior.ControlGroup != filepath.Join("/system.slice", unit) || strings.Contains(prior.ControlGroup, "..") {
		return errors.New("stopped worker observation is not joined to the exact signed prior stop")
	}
	invocationEmpty, groupEmpty := observed.Invocation == "", observed.ControlGroup == ""
	if invocationEmpty != groupEmpty || (!invocationEmpty && (observed.Invocation != strings.ToLower(prior.InvocationID) || observed.ControlGroup != prior.ControlGroup)) {
		return errors.New("stopped worker fields do not preserve the exact signed prior identity")
	}
	return nil
}

func verifyCheckpointPlanBrokerOriginalWorkerTerminal(prior ownedStopReceipt) error {
	if prior.WorkerPID <= 1 || prior.WorkerStartTicks == 0 || !prior.SignalSent || !prior.ReleaseTerminal {
		return errors.New("signed stop receipt lacks terminal original-worker authority")
	}
	_, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(prior.WorkerPID)), prior.WorkerPID)
	return checkpointPlanBrokerOriginalWorkerTerminalResult(prior, err)
}

func checkpointPlanBrokerOriginalWorkerTerminalResult(prior ownedStopReceipt, procErr error) error {
	if prior.WorkerPID <= 1 || prior.WorkerStartTicks == 0 || !prior.SignalSent || !prior.ReleaseTerminal {
		return errors.New("signed stop receipt lacks terminal original-worker authority")
	}
	if errors.Is(procErr, os.ErrNotExist) {
		return nil
	}
	return errors.New("original worker incarnation remains present or its terminal state is uncertain")
}

func checkpointPlanBrokerStoppedWorkerEmpty(ctx context.Context, paths checkpointPlanBrokerPaths, prior ownedStopReceipt) error {
	observed, err := queryCheckpointPlanBrokerStoppedState(ctx, paths)
	if err != nil {
		return errors.New("fixed worker stopped-state proof is incomplete")
	}
	procErr := error(nil)
	_, procErr = checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(prior.WorkerPID)), prior.WorkerPID)
	jobs, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "list-jobs", "--no-legend", "--no-pager")
	jobsErr := err
	if jobsErr == nil && len(jobs) > checkpointUnitMaxOutput {
		jobsErr = errors.New("systemd pending-job state is unavailable")
	}
	group := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(filepath.Clean(prior.ControlGroup), string(os.PathSeparator)), "cgroup.procs")
	body, err := readCheckpointPlanBrokerCgroupProcs(group)
	return verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths, observed, prior, procErr, jobs, jobsErr, body, err, false)
}

func verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths checkpointPlanBrokerPaths, observed checkpointPlanBrokerStoppedState, prior ownedStopReceipt, procErr error, jobs []byte, jobsErr error, cgroupProcs []byte, cgroupErr error, cleanupOnly bool) error {
	var observationErr error
	if cleanupOnly {
		observationErr = verifyCheckpointPlanBrokerStoppedCleanupObservation(observed, paths, prior)
	} else {
		observationErr = verifyCheckpointPlanBrokerStoppedObservation(observed, paths, prior)
	}
	if observationErr != nil || checkpointPlanBrokerOriginalWorkerTerminalResult(prior, procErr) != nil {
		return errors.New("fixed worker stopped-state proof is incomplete")
	}
	if jobsErr != nil || len(jobs) > checkpointUnitMaxOutput {
		return errors.New("systemd pending-job state is unavailable")
	}
	pending, err := checkpointPlanBrokerPendingJobForUnit(jobs, checkpointPlanBrokerUnitName(paths))
	if err != nil {
		return errors.New("systemd pending-job state is malformed")
	}
	if pending {
		return errors.New("fixed worker has a pending systemd job")
	}
	group := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(filepath.Clean(prior.ControlGroup), string(os.PathSeparator)), "cgroup.procs")
	if filepath.Clean(group) != group || cgroupErr != nil || len(bytes.TrimSpace(cgroupProcs)) != 0 {
		return errors.New("fixed worker control group is not confirmed empty")
	}
	return nil
}

func parseCheckpointPlanBrokerUnitState(raw []byte) (checkpointFixedUnitState, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput || raw[len(raw)-1] != '\n' {
		return checkpointFixedUnitState{}, errors.New("fixed plan worker state output is incomplete")
	}
	values := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" || (key != "MainPID" && key != "InvocationID" && key != "ControlGroup" && key != "ActiveState" && key != "SubState") {
			return checkpointFixedUnitState{}, errors.New("fixed plan worker state output is malformed")
		}
		if _, exists := values[key]; exists {
			return checkpointFixedUnitState{}, errors.New("fixed plan worker state has duplicate fields")
		}
		values[key] = value
	}
	if len(values) != 5 {
		return checkpointFixedUnitState{}, errors.New("fixed plan worker state is incomplete")
	}
	pid, err := strconv.Atoi(values["MainPID"])
	if err != nil || pid < 0 || pid == 1 || (pid == 0 && values["ActiveState"] != "inactive" && values["ActiveState"] != "failed") || (pid > 1 && values["ActiveState"] != "active") {
		return checkpointFixedUnitState{}, errors.New("fixed plan worker state is inconsistent")
	}
	return checkpointFixedUnitState{MainPID: pid, Invocation: strings.ToLower(values["InvocationID"]), ControlGroup: values["ControlGroup"], Active: values["ActiveState"], Sub: values["SubState"]}, nil
}

func checkpointPlanBrokerWorkerEmpty(ctx context.Context, paths checkpointPlanBrokerPaths, unit checkpointFixedUnitState) error {
	if unit.MainPID != 0 || (unit.Active != "inactive" && unit.Active != "failed") || unit.ControlGroup == "" || strings.Contains(unit.ControlGroup, "..") || !strings.HasPrefix(unit.ControlGroup, "/") {
		return errors.New("fixed worker is not freshly inactive")
	}
	jobs, err := checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "list-jobs", "--no-legend", "--no-pager")
	if err != nil || len(jobs) > checkpointUnitMaxOutput {
		return errors.New("systemd pending-job state is unavailable")
	}
	pending, err := checkpointPlanBrokerPendingJobForUnit(jobs, checkpointPlanBrokerUnitName(paths))
	if err != nil {
		return errors.New("systemd pending-job state is malformed")
	}
	if pending {
		return errors.New("fixed worker has a pending systemd job")
	}
	group := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(filepath.Clean(unit.ControlGroup), string(os.PathSeparator)), "cgroup.procs")
	body, err := readCheckpointPlanBrokerCgroupProcs(group)
	if err != nil || len(bytes.TrimSpace(body)) != 0 {
		return errors.New("fixed worker control group is not confirmed empty")
	}
	return nil
}

func checkpointPlanBrokerPendingJobForUnit(raw []byte, unit string) (bool, error) {
	if len(raw) > checkpointUnitMaxOutput || unit == "" || filepath.Base(unit) != unit || !strings.HasSuffix(unit, ".service") {
		return false, errors.New("systemd job inventory exceeds its fixed bounds")
	}
	if len(raw) == 0 {
		return false, nil
	}
	if raw[len(raw)-1] != '\n' {
		return false, errors.New("systemd job inventory is incomplete")
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return false, errors.New("systemd job row has an unexpected shape")
		}
		id, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil || id == 0 || fields[1] == "" || fields[2] == "" || fields[3] == "" || strings.ContainsAny(fields[1]+fields[2]+fields[3], "\x00\r\n") {
			return false, errors.New("systemd job row is malformed")
		}
		if fields[1] == unit {
			return true, nil
		}
	}
	return false, nil
}

func readCheckpointPlanBrokerCgroupProcs(path string) ([]byte, error) {
	if filepath.Clean(path) != path || !strings.HasPrefix(path, "/sys/fs/cgroup/") || strings.Contains(path, "..") {
		return nil, errors.New("worker cgroup path is not canonical")
	}
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		// A fixed systemd unit may not have created its cgroup directory yet;
		// with an exact inactive MainPID0 sample and no pending job, absence is
		// the only valid empty-cgroup observation.
		return nil, nil
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("worker cgroup process file is unavailable")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("worker cgroup descriptor is unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return nil, errors.New("worker cgroup process path changed")
	}
	body, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	after, statErr := f.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || len(body) > 64<<10 || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, current) {
		return nil, errors.New("worker cgroup process read was unstable or oversized")
	}
	return body, nil
}

func checkpointPlanBrokerTempPath(dir string) (string, *os.File, error) {
	f, err := os.CreateTemp(dir, ".plan-relaunch-*")
	if err != nil {
		return "", nil, err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return "", nil, err
	}
	return f.Name(), f, nil
}

func checkpointPlanBrokerSyncDir(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Fsync(fd)
}

func checkpointPlanBrokerWriteAtomic(path string, body []byte, mode os.FileMode) error {
	if filepath.Clean(path) != path || !filepath.IsAbs(path) || len(body) == 0 || len(body) > 64<<20 {
		return errors.New("fixed plan broker atomic write is invalid")
	}
	temp, file, err := checkpointPlanBrokerTempPath(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(temp)
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	tempInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temp, path); err != nil {
		return err
	}
	published, publishedInfo, err := readPlanBrokerFile(path, 64<<20, mode)
	if err != nil || !os.SameFile(tempInfo, publishedInfo) || !bytes.Equal(published, body) {
		return errors.New("fixed plan broker atomic publication identity changed")
	}
	return checkpointPlanBrokerSyncDir(filepath.Dir(path))
}

func checkpointPlanBrokerBoundedLines(body []byte, maximum int) ([]string, error) {
	if len(body) == 0 || len(body) > maximum {
		return nil, errors.New("fixed plan broker line input is outside its bound")
	}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 1024), maximum)
	lines := make([]string, 0, 8)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > 256 {
			return nil, errors.New("fixed plan broker line count exceeds its bound")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func checkpointPlanBrokerHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

var _ = bufio.NewScanner
