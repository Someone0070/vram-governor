//go:build linux && checkpoint_local_observer_kernel

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"os/signal"
	"os/user"
	"path/filepath"; "regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
	"vram-governor/internal/checkpointgpuobserver"
)

const (
	checkpointLocalObserverKernelOptIn      = "CHECKPOINT_LOCAL_OBSERVER_KERNEL"
	checkpointLocalObserverKernelChild      = "CHECKPOINT_LOCAL_OBSERVER_KERNEL_CHILD"
	checkpointLocalObserverParentMode       = "CHECKPOINT_LOCAL_OBSERVER_PARENT_MODE"
	checkpointLocalObserverParentNonce      = "CHECKPOINT_LOCAL_OBSERVER_PARENT_NONCE"
	checkpointLocalObserverParentExit       = 73
	checkpointLocalObserverParentFD         = 3
	checkpointLocalObserverWorkerFD         = 4
	checkpointLocalObserverReplaceFD        = 5
	checkpointLocalObserverUnrelatedFD      = 6
	checkpointLocalObserverBrokerFD         = 7
	checkpointLocalObserverRootFD           = 8
	checkpointLocalObserverSentinelFD       = 9
	checkpointLocalObserverReportFD         = 10
	checkpointLocalObserverAckFD            = 11
	checkpointLocalObserverCompletionFD     = 12
	checkpointLocalObserverParentReportFD   = 3
	checkpointLocalObserverParentSentinelFD = 4
	checkpointLocalObserverParentSocketFD   = 5
	checkpointLocalObserverParentOutputLimit = 8 * 1024
)

const (
	checkpointLocalObserverCustodyEmpty             = "custody_empty"
	checkpointLocalObserverCustodyPayloadTruncated  = "custody_payload_truncated"
	checkpointLocalObserverCustodyAncillaryTruncated = "custody_ancillary_truncated"
	checkpointLocalObserverCustodyPayloadFull        = "custody_payload_full"
	checkpointLocalObserverCustodyReceiverUnavailable = "custody_receiver_unavailable"
	checkpointLocalObserverCustodyReceiverTimeout      = "custody_receiver_timeout"
)

type checkpointLocalObserverFixtureUnit struct {
	name       string
	pid        int
	start      uint64
	startedAt  int64
	invocation string
	cgroup     string
	owned      bool
	pidfd      int
}

type checkpointLocalObserverParentOutputCapture struct {
	mu       sync.Mutex
	data     []byte
	total    uint64
	overflow bool
}

func (capture *checkpointLocalObserverParentOutputCapture) Write(p []byte) (int, error) {
	if capture == nil {
		return len(p), nil
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	if ^uint64(0)-capture.total < uint64(len(p)) {
		capture.total = ^uint64(0)
		capture.overflow = true
	} else {
		capture.total += uint64(len(p))
	}
	remaining := checkpointLocalObserverParentOutputLimit - len(capture.data)
	if remaining > 0 {
		writeCount := len(p)
		if writeCount > remaining {
			writeCount = remaining
		}
		capture.data = append(capture.data, p[:writeCount]...)
		if writeCount != len(p) {
			capture.overflow = true
		}
	} else if len(p) != 0 {
		capture.overflow = true
	}
	return len(p), nil
}

func (capture *checkpointLocalObserverParentOutputCapture) snapshot() ([]byte, uint64, bool) {
	if capture == nil {
		return nil, 0, false
	}
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]byte(nil), capture.data...), capture.total, capture.overflow
}

func checkpointLocalObserverParentFailureClass(capture *checkpointLocalObserverParentOutputCapture) string {
	data, total, overflow := capture.snapshot()
	if overflow || total > checkpointLocalObserverParentOutputLimit {
		return "overflow"
	}
	if len(data) == 0 {
		return "unavailable"
	}
	const source = "checkpoint_local_observer_kernel_linux_test.go:"
	lines := strings.Split(string(data), "\n")
	failureHeader := -1
	for index, line := range lines {
		if !strings.HasPrefix(line, "--- FAIL:") {
			continue
		}
		if failureHeader >= 0 || !checkpointLocalObserverParentFailureHeader(line) {
			return "unavailable"
		}
		failureHeader = index
	}
	if failureHeader < 0 {
		return "unavailable"
	}
	found := ""
	for _, line := range lines[failureHeader+1:] {
		if strings.HasPrefix(line, "--- ") || line == "FAIL" {
			break
		}
		if !strings.Contains(line, source) {
			continue
		}
		prefix := "    " + source
		if !strings.HasPrefix(line, prefix) {
			return "unavailable"
		}
		location := strings.TrimPrefix(line, prefix)
		separator := strings.Index(location, ": ")
		if separator <= 0 || separator+2 >= len(location) {
			return "unavailable"
		}
		for _, digit := range location[:separator] {
			if digit < '0' || digit > '9' {
				return "unavailable"
			}
		}
		lineNumber, err := strconv.Atoi(location[:separator])
		if err != nil {
			return "unavailable"
		}
		site := checkpointLocalObserverParentFailureSite(lineNumber)
		if site == "" || found != "" {
			return "unavailable"
		}
		found = site
	}
	if found == "" {
		return "unavailable"
	}
	return found
}

func checkpointLocalObserverParentFailureHeader(line string) bool {
	const prefix = "--- FAIL: TestCheckpointLocalObserverKernelFixture ("
	if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "s)") {
		return false
	}
	duration := strings.TrimSuffix(strings.TrimPrefix(line, prefix), "s)")
	if duration == "" || strings.Count(duration, ".") > 1 || duration[0] == '.' || duration[len(duration)-1] == '.' {
		return false
	}
	digit := false
	for _, character := range duration {
		if character == '.' {
			continue
		}
		if character < '0' || character > '9' {
			return false
		}
		digit = true
	}
	return digit
}

func checkpointLocalObserverParentTerminalClass(pidfd int) string {
	if pidfd < 0 {
		return "unavailable"
	}
	err := checkpointLocalPIDFDAlive(pidfd)
	if err == nil {
		return "live"
	}
	if err.Error() == "held local process exited during attribution" {
		return "terminal"
	}
	return "unavailable"
}

func checkpointLocalObserverCustodyFailureClass(err error) string {
	if err == nil {
		return "custody_result_invalid"
	}
	switch err.Error() {
	case checkpointLocalObserverCustodyEmpty:
		return "empty"
	case checkpointLocalObserverCustodyPayloadTruncated:
		return "payload_truncated"
	case checkpointLocalObserverCustodyAncillaryTruncated:
		return "ancillary_truncated"
	case checkpointLocalObserverCustodyPayloadFull:
		return "payload_full"
	case checkpointLocalObserverCustodyReceiverTimeout:
		return "receiver_timeout"
	case checkpointLocalObserverCustodyReceiverUnavailable:
		return "receiver_unavailable"
	default:
		return "custody_rejected"
	}
}

func TestCheckpointLocalObserverKernelFixture(t *testing.T) {
	if os.Getenv(checkpointLocalObserverKernelOptIn) != "1" {
		t.Fatalf("tagged kernel fixture requires explicit %s=1 admission", checkpointLocalObserverKernelOptIn)
	}
	checkpointLocalObserverParentFailureClassifierControls(t)
	if os.Getenv(checkpointLocalObserverParentMode) == "unit-owning-parent" {
		checkpointLocalObserverKernelFixtureBody(t, true)
		return
	}
	checkpointLocalObserverKernelFixtureBody(t, false)
	checkpointLocalObserverKernelOuterParentDeath(t)
}

const (
	checkpointObserverRouteOptInEnv       = "CHECKPOINT_OBSERVER_ROUTE_KERNEL"
	checkpointObserverRouteChildEnv       = "CHECKPOINT_OBSERVER_ROUTE_CHILD"
	checkpointObserverRouteRootEnv        = "CHECKPOINT_OBSERVER_ROUTE_ROOT"
	checkpointObserverRouteHostBinaryEnv  = "CHECKPOINT_OBSERVER_ROUTE_HOST_TEST_BINARY"
	checkpointObserverRouteHostSocketEnv  = "CHECKPOINT_OBSERVER_ROUTE_HOST_SOCKET"
	checkpointObserverRouteHostConfigEnv  = "CHECKPOINT_OBSERVER_ROUTE_HOST_CONFIG"
	checkpointObserverRouteHostKeyEnv     = "CHECKPOINT_OBSERVER_ROUTE_HOST_KEY"
	checkpointObserverRouteLocalRootEnv   = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_ROOT"
	checkpointObserverRouteLocalSocketEnv = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SOCKET"
	checkpointObserverRouteLocalPolicyEnv = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_POLICY"
	checkpointObserverRouteLocalKeyEnv    = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_KEY"
	checkpointObserverRouteLocalPublicEnv = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_PUBLIC"
	checkpointObserverRouteLocalRootFDEnv = "CHECKPOINT_OBSERVER_ROUTE_LOCAL_ROOT_FD"
	checkpointObserverRouteWorkerChildEnv = "CHECKPOINT_OBSERVER_ROUTE_WORKER_CHILD"
	checkpointObserverRouteParentDeathNonceEnv = "CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_NONCE"
	checkpointObserverRouteFixtureGroupName = "daemon"
	checkpointObserverRouteFixtureGroupID = 1
)

func checkpointObserverRouteFixtureGroup() (*user.Group, uint32, error) {
	group, err := user.LookupGroup(checkpointObserverRouteFixtureGroupName)
	if err != nil { return nil, 0, err }
	groupID, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || group.Name != checkpointObserverRouteFixtureGroupName || group.Gid != "1" || groupID != checkpointObserverRouteFixtureGroupID {
		return nil, 0, errors.New("composed fixture requires the pre-existing daemon group with exact GID 1")
	}
	return group, uint32(groupID), nil
}

func checkpointObserverRoutePathAllowed(key, value, root, localRoot string) bool {
	if value == "" || filepath.Clean(value) != value { return false }
	if key == checkpointObserverRouteRootEnv { return value == root }
	if key == checkpointObserverRouteLocalRootEnv || strings.HasPrefix(key, "CHECKPOINT_OBSERVER_ROUTE_LOCAL_") { return value == localRoot || strings.HasPrefix(value, localRoot+string(os.PathSeparator)) }
	return strings.HasPrefix(value, root+string(os.PathSeparator))
}

func checkpointObserverRoutePathAdmissionControls(t *testing.T) {
	root, localRoot := "/run/observer-route-private", "/run/observer-route-local"
	cases := []struct{name, key, value string; want bool}{
		{"exact outer root", checkpointObserverRouteRootEnv, root, true}, {"host descendant", checkpointObserverRouteHostSocketEnv, root+"/host/observer.sock", true},
		{"local root", checkpointObserverRouteLocalRootEnv, localRoot, true}, {"local descendant", checkpointObserverRouteLocalSocketEnv, localRoot+"/run/observer.sock", true},
		{"wrong outer root value", checkpointObserverRouteRootEnv, root+"/host", false}, {"prefix-only outer root", checkpointObserverRouteRootEnv, root+"suffix", false},
		{"outside path", checkpointObserverRouteHostSocketEnv, "/tmp/outside", false}, {"other key exact root", checkpointObserverRouteHostSocketEnv, root, false},
	}
	for _, control := range cases { if got := checkpointObserverRoutePathAllowed(control.key, control.value, root, localRoot); got != control.want { t.Fatalf("path admission %q=%t, want %t", control.name, got, control.want) } }
}

func TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {
	if os.Getenv(checkpointObserverRouteChildEnv) == "pid1" {
		checkpointObserverRouteComposedPID1(t)
		return
	}
	if os.Getenv(checkpointObserverRouteChildEnv) != "" || os.Getenv(checkpointObserverRouteOptInEnv) != "1" || os.Geteuid() != 0 {
		t.Fatal("composed observer route fixture requires explicit root-only fixed-host admission")
	}
	checkpointObserverRoutePathAdmissionControls(t)
	if err := errors.Join(checkpointObserverRouteRequireInitialHostNamespace(), checkpointObserverRouteNestedFailureReducerControls()); err != nil {
		t.Fatalf("composed observer route initial namespace or nested reducer control failed: %v", err)
	}
	runDev, runInode, err := checkpointObserverRouteHoldRunParent()
	if err != nil {
		t.Fatalf("composed fixture requires the held protected /run ancestry: %v", err)
	}
	checkpointObserverRouteLocalTreeCustodyControls(t)
	checkpointObserverRouteLocalRootOwnerControls(t)
	preservePrivateRoot := false
	runParentFD, err := unix.Open("/run", unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil { t.Fatalf("retain protected /run ancestry descriptor: %v", err) }
	defer func() { if closeErr := checkpointObserverRouteCloseFD(&runParentFD); closeErr != nil { preservePrivateRoot = true; t.Errorf("protected /run parent descriptor close failed: %v", closeErr) } }()
	var heldRun unix.Stat_t
	if err := unix.Fstat(runParentFD, &heldRun); err != nil || uint64(heldRun.Dev) != runDev || heldRun.Ino != runInode || heldRun.Uid != 0 || heldRun.Mode&0022 != 0 {
		t.Fatal("protected /run ancestry changed during descriptor retention")
	}
	checkpointObserverRouteSentinelEarlyOwnerControls(t)
	sentinelFile, err := os.CreateTemp("/run", "checkpoint-observer-route-sentinel-")
	if err != nil {
		t.Fatalf("create exact outside cleanup sentinel: %v", err)
	}
	defer func() { if closeErr := checkpointObserverRouteCloseFile(&sentinelFile); closeErr != nil { t.Errorf("outside sentinel original descriptor settlement failed: %v", closeErr) } }()
	sentinelPath := sentinelFile.Name()
	sentinelBytes := []byte("observer route outside-tree sentinel v1\n")
	sentinelDev,sentinelInode,setupErr:=checkpointObserverRouteSentinelSetup(&sentinelFile,sentinelBytes,checkpointObserverRouteRealSentinelOps(sentinelFile)); if setupErr!=nil { t.Fatalf("outside sentinel setup failed: %v",setupErr) }
	defer func() {
		if sentinelFile == nil { t.Errorf("outside sentinel owner was already settled before identity proof"); return }
		held, heldErr := sentinelFile.Stat()
		heldStat, heldOK := (*syscall.Stat_t)(nil), false
		if heldErr == nil { heldStat, heldOK = held.Sys().(*syscall.Stat_t) }
		if heldErr != nil || !heldOK || uint64(heldStat.Dev) != sentinelDev || heldStat.Ino != sentinelInode || heldStat.Uid != 0 || heldStat.Nlink != 1 {
			t.Errorf("held outside sentinel descriptor identity changed; preserving its current object")
			return
		}
		current, err := os.Lstat(sentinelPath)
		if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 || current.Size() != int64(len(sentinelBytes)) {
			t.Errorf("outside sentinel identity changed; preserving its current object")
			return
		}
		stat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != sentinelDev || stat.Ino != sentinelInode || stat.Uid != 0 || stat.Nlink != 1 {
			t.Errorf("outside sentinel inode changed; preserving its current object")
			return
		}
		if _, err := sentinelFile.Seek(0, io.SeekStart); err != nil {
			t.Errorf("could not reread held outside sentinel: %v", err)
			return
		}
		contents, err := io.ReadAll(io.LimitReader(sentinelFile, int64(len(sentinelBytes)+1)))
		if err != nil || !bytes.Equal(contents, sentinelBytes) {
			t.Errorf("outside sentinel contents changed; preserving its current object")
			return
		}
		if closeErr := checkpointObserverRouteCloseFile(&sentinelFile); closeErr != nil { t.Errorf("could not settle exact outside sentinel descriptor: %v", closeErr); return }
		current, err = os.Lstat(sentinelPath)
		if err != nil { t.Errorf("outside sentinel name became uncertain after descriptor close; preserving it: %v", err); return }
		stat, ok = current.Sys().(*syscall.Stat_t)
		if !ok || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || uint64(stat.Dev) != sentinelDev || stat.Ino != sentinelInode || stat.Uid != 0 || stat.Nlink != 1 { t.Errorf("outside sentinel name changed after descriptor close; preserving current object"); return }
		if err := os.Remove(sentinelPath); err != nil { t.Errorf("could not remove exact outside sentinel: %v", err); return }
		fmt.Println("CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS")
	}()
	root, err := os.MkdirTemp("/run", "checkpoint-observer-route-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	var hostPins []checkpointObserverRouteHeldPath
	defer func() {
		if closeErr := checkpointObserverRouteCloseHeldPaths(hostPins); closeErr != nil {
			t.Errorf("host fixture creation-custody descriptor settlement failed: %v", closeErr)
		}
	}()
	rootPin, err := checkpointObserverRouteCaptureHeldPath(root)
	if err != nil { t.Fatalf("retain created private root identity before later fixture work: %v", err) }
	hostPins = append(hostPins, rootPin)
	rootPin.fd = -1
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := checkpointObserverRouteRefreshHeldPath(&hostPins[0]); err != nil { t.Fatalf("refresh original private root metadata: %v", err) }
	if hostPins[0].uid != 0 || hostPins[0].mode&unix.S_IFMT != unix.S_IFDIR || hostPins[0].mode&0777 != 0700 || checkpointObserverRouteCheckHeldPaths(hostPins) != nil {
		t.Fatalf("composed fixture root is not exact root-owned private creation-custody storage")
	}
	rootDev, rootInode := hostPins[0].dev, hostPins[0].inode
	hostDir := filepath.Join(root, "host")
	if err := os.Mkdir(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	hostDirPin, err := checkpointObserverRouteCaptureHeldPath(hostDir)
	if err != nil { t.Fatalf("retain original host directory immediately after creation: %v", err) }
	hostPins = append(hostPins, hostDirPin)
	hostDirPin.fd = -1
	localRoot, err := os.MkdirTemp("/run", "checkpoint-observer-route-local-")
	if err != nil {
		t.Fatal(err)
	}
	localRootPin, err := checkpointObserverRouteCaptureHeldPath(localRoot)
	if err != nil { t.Fatalf("retain created /run local root before later fixture work: %v", err) }
	defer func() { if closeErr := checkpointObserverRouteCloseHeldPath(&localRootPin); closeErr != nil { t.Errorf("outer local-root custody descriptor settlement failed: %v", closeErr) } }()
	if err := os.Chmod(localRoot, 0711); err != nil {
		t.Fatal(err)
	}
	if err := checkpointObserverRouteRefreshHeldPath(&localRootPin); err != nil { t.Fatalf("refresh original /run local root metadata: %v", err) }
	if localRootPin.uid != 0 || localRootPin.mode&unix.S_IFMT != unix.S_IFDIR || localRootPin.mode&0777 != 0711 || checkpointObserverRouteCheckHeldPaths([]checkpointObserverRouteHeldPath{localRootPin}) != nil {
		t.Fatalf("composed local observer root is not exact root-owned traversable creation custody")
	}
	defer func() {
		if preservePrivateRoot {
			t.Errorf("composed route fixture custody is uncertain; preserving exact private root")
			return
		}
		current, statErr := os.Lstat(root)
		if statErr != nil || current.Mode()&os.ModeSymlink != 0 {
			t.Errorf("composed route private root identity is unavailable; preserving fixture")
			return
		}
		stat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != rootDev || stat.Ino != rootInode || stat.Uid != 0 || current.Mode().Perm() != 0700 {
			t.Errorf("composed route private root changed; preserving fixture")
			return
		}
		if err := checkpointObserverRouteRequireHeldRunParent(runDev, runInode); err != nil || unix.Fstat(runParentFD, &heldRun) != nil || uint64(heldRun.Dev) != runDev || heldRun.Ino != runInode || heldRun.Uid != 0 || heldRun.Mode&0022 != 0 {
			t.Errorf("protected /run ancestry changed; preserving private fixture roots: %v", err)
			return
		}
		for _, name := range []string{filepath.Join(hostDir, "observer.sock"), filepath.Join(hostDir, "observer.sock.ready"), filepath.Join(localRoot, "run", "observer.sock")} {
			if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("composed host listener state is uncertain; preserving fixture")
				return
			}
		}
		if len(hostPins) != 6 {
			t.Errorf("host fixture creation-time descriptor pins are unavailable; preserving fixture")
			return
		}
		if _, err := os.Lstat(localRoot); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("local fixture tree was not removed by its exact held-descriptor cleanup; preserving fixture")
			return
		}
		if err := checkpointObserverRouteRemoveExactPrivateTree(root, hostDir, rootDev, rootInode, hostPins); err != nil {
			t.Errorf("could not remove exact composed host private tree: %v; preserving fixture", err)
			return
		}
		if closeErr := checkpointObserverRouteCloseHeldPaths(hostPins); closeErr != nil {
			t.Errorf("host fixture held-path settlement failed after exact removal: %v", closeErr)
			return
		}
		if closeErr := checkpointObserverRouteCloseFD(&runParentFD); closeErr != nil {
			preservePrivateRoot = true
			t.Errorf("protected /run parent descriptor settlement failed before success: %v", closeErr)
			return
		}
		fmt.Println("CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY")
	}()
	var server *exec.Cmd
	var serverDone chan error
	var serverPIDFD = -1
	serverReaped := false

	hostBinary := os.Getenv(checkpointObserverRouteHostBinaryEnv)
	if err := checkpointObserverRouteValidateHostBinary(hostBinary); err != nil {
		t.Fatalf("composed observer route host test binary failed private-path custody: %v", err)
	}
	hostSocket := filepath.Join(hostDir, "observer.sock")
	hostConfigPath := filepath.Join(hostDir, "policy.json")
	hostKeyPath := filepath.Join(hostDir, "observer.key")
	hostPublicPath := filepath.Join(hostDir, "observer.pub")
	localConf := filepath.Join(localRoot, "conf")
	localKeys := filepath.Join(localRoot, "signing")
	localRun := filepath.Join(localRoot, "run")
	localSocket := filepath.Join(localRun, "observer.sock")
	localPolicy := filepath.Join(localConf, "policy.json")
	localKey := filepath.Join(localKeys, "observer.key")
	localPublic := filepath.Join(localConf, "observer.pub")
	for key, value := range map[string]string{
		checkpointObserverRouteRootEnv: root, checkpointObserverRouteHostSocketEnv: hostSocket,
		checkpointObserverRouteHostConfigEnv: hostConfigPath, checkpointObserverRouteHostKeyEnv: hostKeyPath,
		checkpointObserverRouteLocalRootEnv: localRoot,
		checkpointObserverRouteLocalSocketEnv: localSocket, checkpointObserverRouteLocalPolicyEnv: localPolicy,
		checkpointObserverRouteLocalKeyEnv: localKey, checkpointObserverRouteLocalPublicEnv: localPublic,
	} {
		if !checkpointObserverRoutePathAllowed(key, value, root, localRoot) {
			t.Fatalf("composed fixture path %s escaped its exact private root", key)
		}
	}
	hostFilePins, err := checkpointObserverRouteWriteHostAuthority(hostConfigPath, hostKeyPath, hostPublicPath, hostSocket)
	if err != nil {
		t.Fatalf("prepare exact synthetic host authority: %v", err)
	}
	hostPins = append(hostPins, hostFilePins...)

	serverExecutable := hostBinary
	server = exec.Command(serverExecutable, "-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$", "-test.count=1", "-test.timeout=95s")
	server.SysProcAttr = &syscall.SysProcAttr{PidFD: &serverPIDFD, Pdeathsig: syscall.SIGKILL}
	hostParentFD, err := unix.Dup(hostPins[1].fd)
	if err != nil { t.Fatalf("duplicate original host-directory creation capability for exact child handoff: %v", err) }
	hostParentFile := os.NewFile(uintptr(hostParentFD), "checkpoint-observer-route-host-parent")
	server.ExtraFiles = []*os.File{hostParentFile}
	server.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", "CHECKPOINT_GPU_OBSERVER_FIXTURE_CHILD=route-server", "CHECKPOINT_OBSERVER_ROUTE_HOST_CHILD=1", "CHECKPOINT_OBSERVER_ROUTE_HOST_SOCKET=" + hostSocket, "CHECKPOINT_OBSERVER_ROUTE_HOST_CONFIG=" + hostConfigPath, "CHECKPOINT_OBSERVER_ROUTE_HOST_KEY=" + hostKeyPath, "CHECKPOINT_OBSERVER_ROUTE_HOST_PARENT_FD=3"}
	serverOutput := &checkpointLocalObserverLimitedBuffer{}
	server.Stdout, server.Stderr = serverOutput, serverOutput
	if err := server.Start(); err != nil {
		closeErr := checkpointObserverRouteCloseFile(&hostParentFile)
		t.Fatalf("could not start exact host observer fixture child: %v", errors.Join(err, closeErr))
	}
	serverDone = make(chan error, 1)
	go func() { serverDone <- server.Wait() }()
	defer func() {
		if !serverReaped && serverPIDFD >= 0 {
			if _, stopErr := checkpointObserverRouteStopAndWait(serverPIDFD, serverDone, 4*time.Second); stopErr != nil { preservePrivateRoot = true } else { serverReaped = true }
		}
		if closeErr := checkpointObserverRouteCloseFD(&serverPIDFD); closeErr != nil { preservePrivateRoot = true; t.Errorf("host server pidfd close failed: %v", closeErr) }
		if !serverReaped {
			preservePrivateRoot = true
		}
	}()
	if err := checkpointObserverRouteCloseFile(&hostParentFile); err != nil {
		preservePrivateRoot = true
		t.Fatalf("parent copy of original host-directory capability did not settle after child handoff: %v", err)
	}
	serverPID := server.Process.Pid
	if serverPIDFD < 0 || checkpointLocalObserverPidfdTarget(serverPIDFD) != serverPID || checkpointLocalPIDFDAlive(serverPIDFD) != nil {
		t.Fatalf("host observer fixture child has no matching original pidfd")
	}
	serverStart, serverStartErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(serverPID)), serverPID)
	if serverStartErr != nil || serverStart == 0 {
		t.Fatalf("host observer fixture child start identity is unavailable")
	}
	readyPath := hostSocket + ".ready"
	ready := false
	readyDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(readyDeadline) {
		if info, statErr := os.Lstat(readyPath); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 {
			marker, readErr := os.ReadFile(readyPath)
			ready = readErr == nil && string(marker) == "ready\n"
			if ready {
				break
			}
		}
		if checkpointLocalPIDFDAlive(serverPIDFD) != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	readyServerStart, readyServerStartErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(serverPID)), serverPID)
	if !ready || readyServerStartErr != nil || readyServerStart != serverStart || checkpointLocalObserverPidfdTarget(serverPIDFD) != serverPID {
		t.Fatalf("actual host handler did not reach its bounded ready state under the original pidfd")
	}

	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		t.Fatal("composed node test executable identity is unavailable")
	}
	_, groupID, err := checkpointObserverRouteFixtureGroup()
	if err != nil { t.Fatalf("fixed composed fixture group identity is unavailable: %v", err) }
	nested := exec.Command(executable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedKernelFixture$", "-test.count=1", "-test.timeout=85s")
	var nestedPIDFD int
	nestedPIDFD = -1
	nested.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 65534, HostID: 65534, Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 65534, HostID: 65534, Size: 1}, {ContainerID: int(groupID), HostID: int(groupID), Size: 1}},
		GidMappingsEnableSetgroups: false, Credential: &syscall.Credential{Uid: 0, Gid: groupID, NoSetGroups: true}, PidFD: &nestedPIDFD, Pdeathsig: syscall.SIGKILL,
	}
	localRootFD, err := unix.Dup(localRootPin.fd)
	if err != nil { t.Fatalf("duplicate original local-root custody for inherited PID1 handoff: %v", err) }
	localRootFile := os.NewFile(uintptr(localRootFD), "checkpoint-observer-route-local-root")
	nested.ExtraFiles = []*os.File{localRootFile}
	nested.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", checkpointObserverRouteChildEnv + "=pid1", checkpointObserverRouteRootEnv + "=" + root,
		checkpointObserverRouteLocalRootFDEnv + "=3",
		checkpointObserverRouteHostSocketEnv + "=" + hostSocket, checkpointObserverRouteHostConfigEnv + "=" + hostConfigPath,
		checkpointObserverRouteHostKeyEnv + "=" + hostKeyPath, checkpointObserverRouteLocalRootEnv + "=" + localRoot,
		checkpointObserverRouteLocalSocketEnv + "=" + localSocket,
		checkpointObserverRouteLocalPolicyEnv + "=" + localPolicy, checkpointObserverRouteLocalKeyEnv + "=" + localKey,
		checkpointObserverRouteLocalPublicEnv + "=" + localPublic}
	nestedOutput := &checkpointLocalObserverLimitedBuffer{}
	nested.Stdout, nested.Stderr = nestedOutput, nestedOutput
	if err := nested.Start(); err != nil {
		closeErr := checkpointObserverRouteCloseFile(&localRootFile)
		_ = unix.PidfdSendSignal(serverPIDFD, unix.SIGTERM, nil, 0)
		select {
		case <-serverDone:
			serverReaped = true
		case <-time.After(3 * time.Second):
			preservePrivateRoot = true
		}
		t.Fatalf("could not start exact nested route fixture child: %v", errors.Join(err, closeErr))
	}
	nestedDone := make(chan error, 1)
	nestedReaped := false
	go func() { nestedDone <- nested.Wait() }()
	defer func() {
		if !nestedReaped && nestedPIDFD >= 0 {
			if _, stopErr := checkpointObserverRouteStopAndWait(nestedPIDFD, nestedDone, 4*time.Second); stopErr != nil { preservePrivateRoot = true } else { nestedReaped = true }
		}
		if closeErr := checkpointObserverRouteCloseFD(&nestedPIDFD); closeErr != nil { preservePrivateRoot = true; t.Errorf("nested child pidfd close failed: %v", closeErr) }
		if !nestedReaped {
			preservePrivateRoot = true
		}
	}()
	if err := checkpointObserverRouteCloseFile(&localRootFile); err != nil { preservePrivateRoot = true; t.Fatalf("close parent copy of inherited local-root capability: %v", err) }
	select {
	case err := <-nestedDone:
		nestedReaped = true
		if err != nil {
			_ = unix.PidfdSendSignal(serverPIDFD, syscall.SIGTERM, nil, 0)
			select {
			case <-serverDone:
				serverReaped = true
			case <-time.After(3 * time.Second):
				preservePrivateRoot = true
			}
			t.Fatalf("composed nested route fixture failed: %v\n%s\n%s", err, boundedLocalObserverText(nestedOutput.data), checkpointObserverRouteNestedFailureDiagnostic(err, nestedOutput))
		}
	case <-time.After(86 * time.Second):
		_ = unix.PidfdSendSignal(nestedPIDFD, syscall.SIGTERM, nil, 0)
		select {
		case <-nestedDone:
			nestedReaped = true
		case <-time.After(4 * time.Second):
			preservePrivateRoot = true
			t.Fatalf("nested fixture wait is uncertain; preserving exact private root")
		}
		_ = unix.PidfdSendSignal(serverPIDFD, syscall.SIGTERM, nil, 0)
		t.Fatalf("composed nested route fixture exceeded its fixed bound; preserving private root")
	}
	if nestedPIDFD < 0 || checkpointLocalPIDFDAlive(nestedPIDFD) == nil {
		t.Fatalf("nested fixture child lost its original pidfd custody")
	}
	if strings.Count(string(nestedOutput.data), "CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS") != 1 || strings.Count(string(nestedOutput.data), "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS") != 1 {
		t.Fatalf("nested fixture did not prove one signed nonroot managed route: %s", boundedLocalObserverText(nestedOutput.data))
	}
	if _, err := os.Lstat(localRoot); !errors.Is(err, os.ErrNotExist) {
		preservePrivateRoot = true
		t.Fatalf("local fixture tree did not disappear after exact child cleanup: %v", err)
	}
	if closeErr := checkpointObserverRouteCloseHeldPath(&localRootPin); closeErr != nil {
		preservePrivateRoot = true
		t.Fatalf("outer local-root creation capability did not settle before success: %v", closeErr)
	}
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS")
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS")
	select {
	case err := <-serverDone:
		serverReaped = true
		if err != nil || strings.Count(string(serverOutput.data), "CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2") != 1 {
			t.Fatalf("actual host handler did not complete exactly two stable collector joins: err=%v output=%s", err, boundedLocalObserverText(serverOutput.data))
		}
	case <-time.After(8 * time.Second):
		_ = unix.PidfdSendSignal(serverPIDFD, syscall.SIGTERM, nil, 0)
		t.Fatalf("host handler did not settle after the nested signed client; preserving private root")
	}
	if checkpointLocalPIDFDAlive(serverPIDFD) == nil || checkpointLocalPIDFDAlive(nestedPIDFD) == nil {
		t.Fatalf("composed fixture child remained live after successful Wait")
	}
	if err := checkpointObserverRouteParentDeathControl(executable); err != nil {
		t.Fatalf("composed parent-death/reap control failed: %v", err)
	}
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS")
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2")
}

func checkpointObserverRouteHoldRunParent() (uint64, uint64, error) {
	info, err := os.Lstat("/run")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return 0, 0, errors.New("/run is missing, writable by group/world, or not a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink < 2 {
		return 0, 0, errors.New("/run is not held root-owned directory custody")
	}
	return uint64(stat.Dev), stat.Ino, nil
}

func checkpointObserverRouteRequireHeldRunParent(dev, inode uint64) error {
	current, err := os.Lstat("/run")
	if err != nil || !current.IsDir() || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm()&0022 != 0 {
		return errors.New("/run parent changed type or became group/world writable")
	}
	stat, ok := current.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != dev || stat.Ino != inode || stat.Uid != 0 {
		return errors.New("/run parent held identity changed")
	}
	return nil
}

func checkpointObserverRouteWriteHostAuthority(configPath, keyPath, publicPath, socketPath string) ([]checkpointObserverRouteHeldPath, error) {
	self, err := os.Executable()
	if err != nil || !filepath.IsAbs(self) {
		return nil, errors.New("host route fixture executable is not absolute")
	}
	executable, digest, err := checkpointLocalExecutableIdentity("/proc/self")
	if err != nil || executable != self {
		return nil, errors.New("host route fixture executable pin is unavailable")
	}
	cgroup, err := checkpointReadLocalCgroup("/proc/self")
	if err != nil {
		return nil, errors.New("host route fixture cgroup is unavailable")
	}
	_, groupID, err := checkpointObserverRouteFixtureGroup()
	if err != nil { return nil, err }
	config := checkpointgpuobserver.ObserverConfig{
		Version: checkpointgpuobserver.ProtocolVersion, SocketGID: uint32(groupID),
		PeerAuthorities: []checkpointgpuobserver.PeerAuthority{
			{Role: "node-agent", UID: 65534, ExecutablePath: executable, ExecutableSHA256: digest, CgroupRoots: []string{cgroup}},
			{Role: "fixed-supervisor", UID: 0, ExecutablePath: "/usr/libexec/vram-checkpoint-fixed-supervisor", ExecutableSHA256: strings.Repeat("f", 64), CgroupRoots: []string{cgroup}},
			{Role: "local-observer", UID: 0, ExecutablePath: executable, ExecutableSHA256: digest, CgroupRoots: []string{cgroup}},
		},
		Containers: []checkpointgpuobserver.ContainerAuthority{{CgroupRoot: cgroup, NodeAgentUID: 65534, NodeAgentExecutablePath: executable, NodeAgentExecutableSHA256: digest}},
	}
	configBytes, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	privateDigest := sha256.Sum256(public)
	trustBytes, err := json.Marshal(checkpointNodeObserverTrust{Version: checkpointgpuobserver.ProtocolVersion, SocketPath: socketPath, PublicKeySHA256: hex.EncodeToString(privateDigest[:])})
	if err != nil {
		return nil, err
	}
	var pins []checkpointObserverRouteHeldPath
	fail := func(cause error) ([]checkpointObserverRouteHeldPath, error) { return nil, errors.Join(cause, checkpointObserverRouteCloseHeldPaths(pins)) }
	for _, item := range []struct {
		path string
		data []byte
	}{{configPath, configBytes}, {keyPath, private}, {publicPath, public}, {filepath.Join(filepath.Dir(configPath), "trust.json"), trustBytes}} {
		pin, err := checkpointObserverRouteCreateHeldFixtureFile(item.path, item.data, 0, 0, 0600)
		if err != nil { return fail(err) }
		pins = append(pins, pin)
	}
	return pins, nil
}

func checkpointObserverRouteRequireInitialHostNamespace() error {
	if os.Geteuid() != 0 {
		return errors.New("composed observer route fixture requires root")
	}
	self, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return fmt.Errorf("read self PID namespace: %w", err)
	}
	init, err := os.Stat("/proc/1/ns/pid")
	if err != nil {
		return fmt.Errorf("read PID 1 namespace: %w", err)
	}
	selfStat, selfOK := self.Sys().(*syscall.Stat_t)
	initStat, initOK := init.Sys().(*syscall.Stat_t)
	if !selfOK || !initOK || selfStat.Ino != initStat.Ino || selfStat.Ino != 4026531836 {
		return errors.New("composed observer route fixture is not in the initial host PID namespace")
	}
	return nil
}

func checkpointObserverRouteValidateHostBinary(binary string) (result error) {
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary || filepath.Base(binary) != "checkpoint-observer-host.test" {
		return errors.New("host test binary path is not the fixed generated name")
	}
	directory := filepath.Dir(binary)
	directoryName := filepath.Base(directory)
	if !strings.HasPrefix(directoryName, "checkpoint-observer-route-build-") && !strings.HasPrefix(directoryName, "checkpoint-observer-route-upload-") {
		return errors.New("host test binary directory is outside the fixed private build namespace")
	}
	dirInfo, err := os.Lstat(directory)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 || dirInfo.Mode().Perm() != 0700 {
		return errors.New("host test binary parent is not a private non-symlink directory")
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || dirStat.Uid != 0 {
		return errors.New("host test binary parent is not root-owned")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > 128<<20 {
		return errors.New("host test binary has unsafe type, mode, or bounded size")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		return errors.New("host test binary is not a single-link root-owned file")
	}
	fd, err := unix.Open(binary, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("host test binary could not be pinned without following links")
	}
	defer func() { owned := fd; fd = -1; result = errors.Join(result, unix.Close(owned)) }()
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil || held.Dev != stat.Dev || held.Ino != stat.Ino || held.Uid != stat.Uid || held.Nlink != stat.Nlink || held.Size != stat.Size || held.Mode != stat.Mode {
		return errors.New("host test binary changed during fixed-path validation")
	}
	return nil
}

func checkpointObserverRoutePublishClientBinary(source, destination string, destinationGID uint32) (digestResult string, result error) {
	return checkpointObserverRoutePublishClientBinaryUsing(source, destination, destinationGID, nil)
}

func checkpointObserverRoutePublishClientBinaryHeld(source, destination string, destinationGID uint32) (string, checkpointObserverRouteHeldPath, error) {
	pin := checkpointObserverRouteHeldPath{fd: -1}; digest, err := checkpointObserverRoutePublishClientBinaryUsing(source, destination, destinationGID, func(_ int, held syscall.Stat_t) error {
		candidate, err := checkpointObserverRouteCaptureHeldPath(destination); if err != nil { return err }
		if !checkpointObserverRouteClientPinMatches(candidate, destination, held) { return errors.Join(errors.New("published client O_PATH pin differs from final writer identity"), checkpointObserverRouteCloseHeldPath(&candidate)) }
		pin = candidate
		return nil
	})
	if err != nil { return "", checkpointObserverRouteHeldPath{}, errors.Join(err, checkpointObserverRouteCloseHeldPath(&pin)) }
	return digest, pin, nil
}

func checkpointObserverRouteClientPinMatches(pin checkpointObserverRouteHeldPath, path string, held syscall.Stat_t) bool {
	return pin.path == path && pin.fd >= 0 && !pin.isDir && pin.dev == uint64(held.Dev) && pin.inode == held.Ino && pin.uid == held.Uid && pin.gid == held.Gid && pin.mode == uint32(held.Mode) && pin.nlink == uint64(held.Nlink) && pin.size == held.Size
}

func checkpointObserverRoutePublishClientBinaryUsing(source, destination string, destinationGID uint32,
	holdCreated func(int, syscall.Stat_t) error) (digestResult string, result error) {
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || filepath.Base(destination) != "nodeagent.test" || filepath.Clean(destination) != destination {
		return "", errors.New("client test executable source or publication path is not canonical")
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 || sourceInfo.Size() <= 0 || sourceInfo.Size() > 128<<20 || sourceInfo.Mode().Perm()&0111 == 0 {
		return "", errors.New("client test executable is not a bounded executable regular file")
	}
	sourceStat, ok := sourceInfo.Sys().(*syscall.Stat_t)
	if !ok || sourceStat.Uid != 0 || sourceStat.Nlink != 1 {
		return "", errors.New("client test executable is not a single-link root-owned file")
	}
	sourceFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("client test executable could not be opened without following links")
	}
	defer func() { owned := sourceFD; sourceFD = -1; result = errors.Join(result, unix.Close(owned)) }()
	var heldSource syscall.Stat_t
	if err := syscall.Fstat(sourceFD, &heldSource); err != nil || heldSource.Dev != sourceStat.Dev || heldSource.Ino != sourceStat.Ino || heldSource.Size != sourceInfo.Size() || heldSource.Uid != 0 || heldSource.Nlink != 1 {
		return "", errors.New("client executable held identity changed before publication")
	}
	contents := make([]byte, sourceInfo.Size())
	for offset := 0; offset < len(contents); {
		count, readErr := unix.Pread(sourceFD, contents[offset:], int64(offset))
		if readErr != nil || count <= 0 {
			return "", errors.New("client executable bounded copy read made no progress")
		}
		offset += count
	}
	digest := sha256.Sum256(contents)
	destinationFD, err := unix.Open(destination, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return "", errors.New("client executable publication path was not exclusively created")
	}
	defer func() { owned := destinationFD; destinationFD = -1; result = errors.Join(result, unix.Close(owned)) }()
	writeErr := error(nil)
	for offset := 0; offset < len(contents); {
		count, err := unix.Write(destinationFD, contents[offset:])
		if err != nil || count <= 0 {
			writeErr = errors.New("client executable publication write made no progress")
			break
		}
		offset += count
	}
	if writeErr == nil {
		writeErr = unix.Fchown(destinationFD, 0, int(destinationGID))
	}
	if writeErr == nil {
		writeErr = unix.Fchmod(destinationFD, 0555)
	}
	if writeErr == nil {
		writeErr = unix.Fsync(destinationFD)
	}
	var heldDestination syscall.Stat_t
	if err := syscall.Fstat(destinationFD, &heldDestination); writeErr == nil && err != nil {
		writeErr = err
	}
	if writeErr != nil || heldDestination.Uid != 0 || heldDestination.Gid != destinationGID || heldDestination.Nlink != 1 || heldDestination.Size != int64(len(contents)) || heldDestination.Mode&0777 != 0555 {
		return "", errors.New("client executable published bytes or permissions are uncertain")
	}
	pathInfo, err := os.Lstat(destination)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Size() != int64(len(contents)) {
		return "", errors.New("client executable published path is not a regular file")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Dev != heldDestination.Dev || pathStat.Ino != heldDestination.Ino || pathStat.Uid != 0 || pathStat.Gid != destinationGID || pathStat.Nlink != 1 || pathStat.Mode&0777 != 0555 {
		return "", errors.New("client executable published path differs from its held inode")
	}
	publishedBytes := make([]byte, len(contents))
	for offset := 0; offset < len(publishedBytes); {
		count, readErr := unix.Pread(destinationFD, publishedBytes[offset:], int64(offset))
		if readErr != nil || count <= 0 {
			return "", errors.New("published client executable could not be reread from its held file")
		}
		offset += count
	}
	publishedDigest := sha256.Sum256(publishedBytes)
	if !bytes.Equal(publishedBytes, contents) || publishedDigest != digest {
		return "", errors.New("published client executable bytes differ from pinned source bytes")
	}
	var finalSource syscall.Stat_t
	if err := syscall.Fstat(sourceFD, &finalSource); err != nil || finalSource.Dev != heldSource.Dev || finalSource.Ino != heldSource.Ino || finalSource.Size != heldSource.Size {
		return "", errors.New("client executable source identity changed during publication")
	}
	var finalDestination syscall.Stat_t
	if err := syscall.Fstat(destinationFD, &finalDestination); err != nil || finalDestination.Dev != heldDestination.Dev || finalDestination.Ino != heldDestination.Ino || finalDestination.Uid != 0 || finalDestination.Gid != destinationGID || finalDestination.Nlink != 1 || finalDestination.Size != heldDestination.Size || finalDestination.Mode&0777 != 0555 {
		return "", errors.New("published client executable held identity changed during reread")
	}
	if holdCreated != nil {
		if err := holdCreated(destinationFD, finalDestination); err != nil { return "", errors.Join(errors.New("original published client custody could not be adopted by tree owner"), err) }
	}
	return hex.EncodeToString(publishedDigest[:]), nil
}

func checkpointObserverRouteRequireExactNames(directory string, expected []string) error {
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(expected) {
		return errors.New("private fixture directory has missing or unexpected entries")
	}
	actual := make([]string, len(entries))
	for index, entry := range entries {
		actual[index] = entry.Name()
	}
	sort.Strings(actual)
	wanted := append([]string(nil), expected...)
	sort.Strings(wanted)
	if !slices.Equal(actual, wanted) {
		return errors.New("private fixture directory entry names changed")
	}
	return nil
}

func checkpointObserverRouteRequireOwnedDirectory(directory string, mode os.FileMode, gid uint32) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		return errors.New("private fixture directory type or mode changed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid || stat.Nlink < 2 {
		return errors.New("private fixture directory owner or link state changed")
	}
	return nil
}

func checkpointObserverRouteRequireOwnedFile(file string, mode os.FileMode, gid uint32, maxBytes int64) error {
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode || info.Size() <= 0 || info.Size() > maxBytes {
		return errors.New("private fixture file type, mode, or size changed")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid || stat.Nlink != 1 {
		return errors.New("private fixture file owner or link state changed")
	}
	return nil
}

type checkpointObserverRouteHeldPath struct {
	path string
	fd int
	dev, inode uint64
	uid, gid uint32
	mode uint32
	isDir bool
	nlink uint64
	size int64
}

func checkpointObserverRouteCaptureHeldPaths(paths []string) ([]checkpointObserverRouteHeldPath, error) {
	pins := make([]checkpointObserverRouteHeldPath, 0, len(paths))
	closeOnError := func(cause error) ([]checkpointObserverRouteHeldPath, error) {
		return nil, errors.Join(cause, checkpointObserverRouteCloseHeldPaths(pins))
	}
	for _, name := range paths {
		pin, err := checkpointObserverRouteCaptureHeldPath(name)
		if err != nil { return closeOnError(err) }
		pins = append(pins, pin)
	}
	return pins, nil
}

func checkpointObserverRouteCaptureHeldPath(name string) (pin checkpointObserverRouteHeldPath, result error) {
	if filepath.Clean(name) != name { return pin, errors.New("owned fixture path is not canonical") }
	fd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil { return pin, errors.New("owned fixture entry could not be retained without following links") }
	fdOwner := fd
	defer func() { result = errors.Join(result, checkpointObserverRouteCloseFD(&fdOwner)) }()
	var held unix.Stat_t
	if err := unix.Fstat(fdOwner, &held); err != nil { return pin, errors.Join(errors.New("owned fixture descriptor could not be identified"), err) }
	isDir := held.Mode&unix.S_IFMT == unix.S_IFDIR
	if !isDir && held.Mode&unix.S_IFMT != unix.S_IFREG { return pin, errors.New("owned fixture entry is not a regular file or directory") }
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != isDir { return pin, errors.New("owned fixture name disappeared, changed type, or became a link") }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino { return pin, errors.New("owned fixture inode changed while its descriptor was retained") }
	pin = checkpointObserverRouteHeldPath{path: name, fd: fdOwner, dev: held.Dev, inode: held.Ino, uid: held.Uid, gid: held.Gid,
		mode: held.Mode, isDir: isDir, nlink: uint64(held.Nlink), size: int64(held.Size)}
	fdOwner = -1
	return pin, nil
}

func checkpointObserverRouteHeldPathFromFD(name string, fd int) (checkpointObserverRouteHeldPath, error) {
	if fd < 0 || filepath.Clean(name) != name { return checkpointObserverRouteHeldPath{}, errors.New("inherited creation capability or path is invalid") }
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Uid != 0 {
		return checkpointObserverRouteHeldPath{}, errors.Join(errors.New("inherited local root capability is not a held root-owned directory"), err)
	}
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() { return checkpointObserverRouteHeldPath{}, errors.New("inherited local root path is absent, substituted, or not a directory") }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino || stat.Uid != held.Uid || stat.Gid != held.Gid || uint32(stat.Mode) != held.Mode {
		return checkpointObserverRouteHeldPath{}, errors.New("inherited local root path differs from its outer creation capability")
	}
	return checkpointObserverRouteHeldPath{path: name, fd: fd, dev: held.Dev, inode: held.Ino, uid: held.Uid, gid: held.Gid,
		mode: held.Mode, isDir: true, nlink: uint64(held.Nlink), size: int64(held.Size)}, nil
}

func checkpointObserverRouteAdoptLocalRootFD(rawFD *int, name string) (checkpointObserverRouteHeldPath, error) {
	if rawFD == nil || *rawFD < 0 { return checkpointObserverRouteHeldPath{}, errors.New("inherited local-root descriptor has no live original owner") }
	pin, err := checkpointObserverRouteHeldPathFromFD(name, *rawFD)
	if err != nil { return checkpointObserverRouteHeldPath{}, err }
	if pin.mode&0777 != 0711 { return checkpointObserverRouteHeldPath{}, errors.New("inherited outer local-root mode is invalid") }
	*rawFD = -1
	return pin, nil
}

func checkpointObserverRouteLocalRootOwnerControls(t *testing.T) {
	for _, mode := range []int{0, 1, 2} {
		failAdoption, closeFault := mode == 1, mode == 2
		label := "positive"; if failAdoption { label = "validation-failure" }; if closeFault { label = "old-pin-close-error" }
		root, err := os.MkdirTemp("/run", "checkpoint-observer-route-fd-control-"); if err != nil { t.Fatal(err) }
		var pin checkpointObserverRouteHeldPath; pinKnown, active := false, true
		t.Cleanup(func() {
			if !active { return }
			if !pinKnown { t.Errorf("%s root creation identity unavailable; preserving uncertain object", label); return }
			info, statErr := os.Lstat(root)
			if statErr == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir() {
				if stat, ok := info.Sys().(*syscall.Stat_t); ok && uint64(stat.Dev) == pin.dev && stat.Ino == pin.inode {
					if removeErr := os.Remove(root); removeErr != nil { t.Errorf("%s exact owned root cleanup: %v", label, removeErr) }
				} else { t.Errorf("%s root name changed; preserving uncertain object", label) }
			} else if !errors.Is(statErr, os.ErrNotExist) { t.Errorf("%s root identity unavailable; preserving it: %v", label, statErr) }
			if closeErr := checkpointObserverRouteCloseHeldPath(&pin); closeErr != nil { t.Errorf("%s root descriptor settlement: %v", label, closeErr) }
		})
		pin, err = checkpointObserverRouteCaptureHeldPath(root); if err != nil { t.Fatalf("%s root could not immediately retain creation identity: %v", label, err) }; pinKnown = true
		if err := os.Chmod(root, 0711); err != nil { t.Fatal(err) }
		var raw int = -1
		if failAdoption {
			raw, err = unix.Open(root, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
			if err != nil { t.Fatal(err) }
			rawOwner := &raw
			t.Cleanup(func() { if closeErr := checkpointObserverRouteCloseFD(rawOwner); closeErr != nil { t.Errorf("raw inherited capability settlement: %v", closeErr) } })
			_, err = checkpointObserverRouteAdoptLocalRootFD(&raw, filepath.Join(root, "substituted"))
			if err == nil || !strings.Contains(err.Error(), "path is absent") || raw < 0 { t.Fatalf("actual adoption validation missed intended error or lost owner: %v", err) }
			before := raw
			if closeErr := checkpointObserverRouteCloseFD(&raw); closeErr != nil || raw != -1 { t.Fatalf("raw owner did not clear before one close: %v", closeErr) }
			if closeErr := checkpointObserverRouteCloseFD(&raw); closeErr != nil || before < 0 { t.Fatalf("cleared raw owner was retried: %v", closeErr) }
			info, statErr := os.Lstat(root); if statErr != nil || info.Sys().(*syscall.Stat_t).Ino != pin.inode { t.Fatal("failed adoption changed the original named root") }
		} else {
			raw, err = unix.Open(root, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0); if err != nil { t.Fatal(err) }
			rawOwner := &raw
			t.Cleanup(func() { if closeErr := checkpointObserverRouteCloseFD(rawOwner); closeErr != nil { t.Errorf("raw inherited capability settlement: %v", closeErr) } })
			adopted, adoptErr := checkpointObserverRouteAdoptLocalRootFD(&raw, root)
			if adoptErr != nil || raw != -1 || adopted.fd < 0 { t.Fatalf("actual inherited-capability positive failed: %+v raw=%d err=%v", adopted, raw, adoptErr) }
			adoptedOwner := adopted
			t.Cleanup(func() { if closeErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner); closeErr != nil { t.Errorf("adopted root capability settlement: %v", closeErr) } })
			realCloseErr := checkpointObserverRouteCloseHeldPath(&pin); closeErr := realCloseErr
			if closeFault && realCloseErr == nil { closeErr = errors.New("explicit old-pin close outcome injection") }
			if closeErr != nil { adoptedCloseErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner); if !closeFault || realCloseErr != nil || adoptedCloseErr != nil || !strings.Contains(closeErr.Error(), "explicit old-pin close outcome injection") || adoptedOwner.fd != -1 { t.Fatalf("old-pin close outcome failed to settle both owners: %v", errors.Join(closeErr, adoptedCloseErr)) } } else { pin = adoptedOwner; adoptedOwner.fd = -1 }
			if closeFault { info,statErr:=os.Lstat(root);if statErr!=nil||info.Mode()&os.ModeSymlink!=0||uint64(info.Sys().(*syscall.Stat_t).Dev)!=pin.dev||info.Sys().(*syscall.Stat_t).Ino!=pin.inode{t.Fatal("close-error settlement changed the original named root")} } else if err := checkpointObserverRouteCheckHeldPaths([]checkpointObserverRouteHeldPath{pin}); err != nil { t.Fatal(err) }
		}
		if err := checkpointObserverRouteCloseHeldPath(&pin); err != nil || pin.fd != -1 { t.Fatalf("actual held owner did not clear before close: %v", err) }
		if err := checkpointObserverRouteCloseHeldPath(&pin); err != nil { t.Fatalf("cleared held owner was retried: %v", err) }
		info,statErr:=os.Lstat(root);stat,ok:=(*syscall.Stat_t)(nil),false;if statErr==nil&&info.Mode()&os.ModeSymlink==0{stat,ok=info.Sys().(*syscall.Stat_t)};if statErr!=nil||!ok||!info.IsDir()||uint64(stat.Dev)!=pin.dev||stat.Ino!=pin.inode{t.Fatal("exact created root changed before removal; preserving it")};if err := os.Remove(root); err != nil { t.Fatal(err) }
		active = false
	}
}
func checkpointObserverRouteRefreshHeldPath(pin *checkpointObserverRouteHeldPath) error {
	if pin == nil || pin.fd < 0 { return errors.New("created fixture identity has no live original descriptor") }
	var held unix.Stat_t
	if err := unix.Fstat(pin.fd, &held); err != nil || held.Dev != pin.dev || held.Ino != pin.inode { return errors.Join(errors.New("created fixture descriptor identity changed during finalization"), err) }
	pin.uid, pin.gid, pin.mode = held.Uid, held.Gid, held.Mode
	if !pin.isDir { pin.nlink, pin.size = uint64(held.Nlink), int64(held.Size) }
	return nil
}
func checkpointObserverRouteCreateHeldFixtureFile(name string, contents []byte, uid, gid uint32, mode os.FileMode) (pin checkpointObserverRouteHeldPath, result error) {
	if len(contents) == 0 || len(contents) > 128<<20 || filepath.Clean(name) != name { return pin, errors.New("created fixture file has invalid fixed path or bounded contents") }
	fd, err := unix.Open(name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil { return pin, fmt.Errorf("exclusively create fixture file: %w", err) }
	fdOwner := fd
	defer func() {
		if fdOwner < 0 { return }
		var held unix.Stat_t
		if err := unix.Fstat(fdOwner, &held); err != nil { result = errors.Join(result, errors.New("partial created fixture identity is uncertain; preserving its name"), err) } else if info, err := os.Lstat(name); err != nil { result = errors.Join(result, errors.New("partial created fixture name is uncertain; preserving it"), err) } else if stat, ok := info.Sys().(*syscall.Stat_t); !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino { result = errors.Join(result, errors.New("partial created fixture name no longer identifies its original file; preserving it")) } else if err := os.Remove(name); err != nil { result = errors.Join(result, fmt.Errorf("remove exact partial fixture file: %w", err)) }
		result = errors.Join(result, checkpointObserverRouteCloseFD(&fdOwner))
	}()
	for offset := 0; offset < len(contents); {
		count, writeErr := unix.Write(fd, contents[offset:])
		if writeErr != nil || count <= 0 { return pin, errors.Join(errors.New("created fixture file write made no progress"), writeErr) }
		offset += count
	}
	if err := unix.Fchown(fd, int(uid), int(gid)); err != nil { return pin, err }
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil { return pin, err }
	if err := unix.Fsync(fd); err != nil { return pin, err }
	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil { return pin, err }
	info, err := os.Lstat(name)
	pathStat, ok := (*syscall.Stat_t)(nil), false
	if err == nil { pathStat, ok = info.Sys().(*syscall.Stat_t) }
	if err != nil || !ok || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || uint64(pathStat.Dev) != held.Dev || pathStat.Ino != held.Ino {
		return pin, errors.New("created fixture path no longer names its live original file descriptor")
	}
	pin = checkpointObserverRouteHeldPath{path: name, fd: fd, dev: held.Dev, inode: held.Ino, uid: held.Uid, gid: held.Gid, mode: held.Mode, nlink: uint64(held.Nlink), size: int64(held.Size)}
	fdOwner = -1
	return pin, nil
}
func checkpointObserverRouteCheckHeldPaths(pins []checkpointObserverRouteHeldPath) error {
	for _, pin := range pins {
		var held unix.Stat_t
		if pin.fd < 0 || unix.Fstat(pin.fd, &held) != nil || held.Dev != pin.dev || held.Ino != pin.inode || held.Uid != pin.uid || held.Gid != pin.gid || held.Mode != pin.mode || !pin.isDir && (uint64(held.Nlink) != pin.nlink || int64(held.Size) != pin.size) {
			return errors.New("held fixture descriptor identity changed before exact cleanup")
		}
		info, err := os.Lstat(pin.path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("fixture entry path disappeared or became a link before cleanup")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint64(stat.Dev) != pin.dev || stat.Ino != pin.inode || stat.Uid != pin.uid || stat.Gid != pin.gid || uint32(stat.Mode) != pin.mode || pin.isDir != info.IsDir() || !pin.isDir && (uint64(stat.Nlink) != pin.nlink || info.Size() != pin.size) {
			return errors.New("fixture entry path no longer names its held creation-time inode")
		}
	}
	return nil
}
func checkpointObserverRouteCloseHeldPath(pin *checkpointObserverRouteHeldPath) error {
	if pin == nil || pin.fd < 0 { return nil }
	return checkpointObserverRouteCloseFD(&pin.fd)
}
func checkpointObserverRouteCloseFD(fd *int) error {
	if fd == nil || *fd < 0 { return nil }
	owned := *fd
	*fd = -1
	return unix.Close(owned)
}
func checkpointObserverRouteCloseFile(file **os.File) error {
	if file == nil || *file == nil { return nil }
	owned := *file
	*file = nil
	return owned.Close()
}

type checkpointObserverRouteSentinelOps struct { chmod func()error; write func([]byte)(int,error); sync func()error; stat func()(os.FileInfo,error); close func(**os.File)error }
type checkpointObserverRouteSentinelOwner struct { file *os.File; path string; dev,inode uint64; known,active bool; close func(**os.File)error }
func (owner *checkpointObserverRouteSentinelOwner) settle(cause error) error { var result error; if owner.file!=nil { result=errors.Join(result,owner.close(&owner.file)) }; if !owner.active{return errors.Join(cause,result)}; if !owner.known{return errors.Join(cause,result,errors.New("sentinel original identity unknown; preserving name"))}; info,err:=os.Lstat(owner.path);if err!=nil||info.Mode()&os.ModeSymlink!=0||!info.Mode().IsRegular(){return errors.Join(cause,result,errors.New("sentinel exact name uncertain; preserving it"),err)};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||uint64(stat.Dev)!=owner.dev||stat.Ino!=owner.inode{return errors.Join(cause,result,errors.New("sentinel original identity changed; preserving it"))};if err=os.Remove(owner.path);err!=nil{return errors.Join(cause,result,err)};owner.active=false;return errors.Join(cause,result) }
func checkpointObserverRouteSentinelSetup(file **os.File, contents []byte, ops checkpointObserverRouteSentinelOps) (uint64,uint64,error) {
	settle:=func(cause error)(uint64,uint64,error){return 0,0,errors.Join(cause,ops.close(file))};if err:=ops.chmod();err!=nil{return settle(err)};if n,err:=ops.write(contents);err!=nil{return settle(err)}else if n!=len(contents){return settle(io.ErrShortWrite)};if err:=ops.sync();err!=nil{return settle(err)};info,err:=ops.stat();if err!=nil{return settle(err)};stat,ok:=info.Sys().(*syscall.Stat_t);if !ok||stat.Uid!=0||info.Mode().Perm()!=0600||info.Size()!=int64(len(contents)){return settle(errors.New("sentinel creation identity mismatch"))};return uint64(stat.Dev),stat.Ino,nil
}
func checkpointObserverRouteRealSentinelOps(file *os.File) checkpointObserverRouteSentinelOps { return checkpointObserverRouteSentinelOps{chmod:func()error{return file.Chmod(0600)},write:file.Write,sync:file.Sync,stat:file.Stat,close:checkpointObserverRouteCloseFile} }
type checkpointObserverRouteBadModeInfo struct{os.FileInfo};func(info checkpointObserverRouteBadModeInfo)Mode()os.FileMode{return 0400}
func checkpointObserverRouteSentinelEarlyOwnerControls(t *testing.T) {
	run:=func(fault string,closeFault bool)(*checkpointObserverRouteSentinelOwner,error){file,err:=os.CreateTemp("/run","checkpoint-observer-route-sentinel-control-");if err!=nil{t.Fatal(err)};owner:=&checkpointObserverRouteSentinelOwner{file:file,path:file.Name(),active:true,close:checkpointObserverRouteCloseFile};t.Cleanup(func(){if err:=owner.settle(nil);err!=nil{t.Errorf("sentinel shared-owner cleanup: %v",err)}});info,err:=file.Stat();if err!=nil{t.Fatal(err)};held,ok:=info.Sys().(*syscall.Stat_t);if !ok{t.Fatal("new sentinel lacks creation identity")};owner.dev,owner.inode,owner.known=uint64(held.Dev),held.Ino,true;ops:=checkpointObserverRouteRealSentinelOps(file);cause:=errors.New("explicit injected sentinel operation error: "+fault);if fault=="chmod"{real:=ops.chmod;ops.chmod=func()error{if err:=real();err!=nil{return err};return cause}};if fault=="write"{real:=ops.write;ops.write=func(data []byte)(int,error){n,err:=real(data);if err!=nil{return n,err};return n,cause}};if fault=="sync"{real:=ops.sync;ops.sync=func()error{if err:=real();err!=nil{return err};return cause}};if fault=="stat"{real:=ops.stat;ops.stat=func()(os.FileInfo,error){info,err:=real();if err!=nil{return nil,err};return info,cause}};if fault=="identity"{real:=ops.stat;ops.stat=func()(os.FileInfo,error){info,err:=real();if err!=nil{return nil,err};return checkpointObserverRouteBadModeInfo{info},nil}};if closeFault{real:=ops.close;ops.close=func(f **os.File)error{return errors.Join(real(f),errors.New("explicit injected sentinel close error"))}};owner.close=ops.close;_,_,setupErr:=checkpointObserverRouteSentinelSetup(&owner.file,[]byte("sentinel-owner-control\n"),ops);if fault==""&&setupErr!=nil{t.Fatalf("actual sentinel positive failed: %v",setupErr)};if fault!=""&&fault!="identity"&&(!errors.Is(setupErr,cause)||owner.file!=nil){t.Fatalf("actual %s operation error branch failed: %v",fault,setupErr)};if fault=="identity"&&(setupErr==nil||!strings.Contains(setupErr.Error(),"identity mismatch")||owner.file!=nil){t.Fatalf("invalid returned identity missed actual guard: %v",setupErr)};expected:="sentinel-owner-control\n";if fault=="chmod"{expected=""};current,statErr:=os.Lstat(owner.path);if statErr!=nil||current.Mode()&os.ModeSymlink!=0||uint64(current.Sys().(*syscall.Stat_t).Dev)!=owner.dev||current.Sys().(*syscall.Stat_t).Ino!=owner.inode{t.Fatalf("%s control lost original inode: %v",fault,statErr)};data,readErr:=os.ReadFile(owner.path);if readErr!=nil||string(data)!=expected{t.Fatalf("%s control changed pre-failure contents: %v",fault,readErr)};return owner,setupErr}
	owner,err:=run("",false);if err!=nil{t.Fatal(err)};if err=owner.settle(nil);err!=nil{t.Fatal(err)}
	for _,fault:=range []string{"chmod","write","sync","stat","identity"}{owner,err=run(fault,false);if err==nil{t.Fatalf("sentinel %s operation mutant accepted",fault)};if fault!="identity"&&!strings.Contains(err.Error(),"explicit injected sentinel operation error: "+fault){t.Fatalf("sentinel %s cause lost: %v",fault,err)};if err=owner.settle(err);err==nil||owner.active{t.Fatalf("sentinel %s early-owner cleanup did not preserve cause/remove exact inode: %v",fault,err)}}
	owner,err=run("sync",true);if err==nil||!strings.Contains(err.Error(),"explicit injected sentinel close error")||owner.file!=nil{t.Fatalf("injected close error did not join/clear actual owner: %v",err)};if finishErr:=owner.settle(err);finishErr==nil||owner.active{t.Fatalf("joined sentinel close failure cleanup failed: %v",finishErr)}
}

func checkpointObserverRouteCloseHeldPaths(pins []checkpointObserverRouteHeldPath) error {
	var closeErr error
	for index := range pins {
		closeErr = errors.Join(closeErr, checkpointObserverRouteCloseHeldPath(&pins[index]))
	}
	return closeErr
}

func checkpointObserverRouteRemoveExactPrivateTree(root, hostDir string, rootDev, rootInode uint64, pins []checkpointObserverRouteHeldPath) error {
	if err := checkpointObserverRouteCheckHeldPaths(pins); err != nil { return err }
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0700 {
		return errors.New("host fixture root identity is unavailable")
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(rootStat.Dev) != rootDev || rootStat.Ino != rootInode || rootStat.Uid != 0 || rootStat.Nlink < 2 {
		return errors.New("host fixture root held identity changed")
	}
	if err := checkpointObserverRouteRequireExactNames(root, []string{"host"}); err != nil {
		return err
	}
	if err := checkpointObserverRouteRequireOwnedDirectory(hostDir, 0700, 0); err != nil {
		return err
	}
	if err := checkpointObserverRouteRequireExactNames(hostDir, []string{"observer.key", "observer.pub", "policy.json", "trust.json"}); err != nil {
		return err
	}
	for _, name := range []string{"observer.key", "observer.pub", "policy.json", "trust.json"} {
		if err := checkpointObserverRouteRequireOwnedFile(filepath.Join(hostDir, name), 0600, 0, 64<<10); err != nil {
			return err
		}
	}
	for _, name := range []string{"observer.key", "observer.pub", "policy.json", "trust.json"} {
		if err := os.Remove(filepath.Join(hostDir, name)); err != nil {
			return err
		}
	}
	if err := os.Remove(hostDir); err != nil {
		return err
	}
	if err := os.Remove(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("host fixture root remains after exact removal")
	}
	return nil
}

func checkpointObserverRouteRemoveExactLocalTree(root string, rootDev, rootInode uint64, pins []checkpointObserverRouteHeldPath, mounted ...*checkpointObserverRouteMountedCleanup) error {
	if len(mounted) > 1 { return errors.New("duplicate mounted-bin custody") }; var mountCleanup *checkpointObserverRouteMountedCleanup; if len(mounted) == 1 { mountCleanup = mounted[0] }
	if mountCleanup == nil {
		if err := checkpointObserverRouteCheckHeldPaths(pins); err != nil { return err }
	} else {
		if !mountCleanup.childrenClear || !checkpointObserverRouteUnderlyingBinCurrent(mountCleanup) || !checkpointObserverRouteTmpfsCurrent(mountCleanup.mount) { return errors.New("mounted cleanup lacks children-clear or current dual-bin custody") }
		filtered := make([]checkpointObserverRouteHeldPath, 0, len(pins)); underlyingSeen, mountedSeen := false, false; binPath := filepath.Join(root, "bin")
		for _, pin := range pins { if pin.path == binPath && pin.dev == mountCleanup.underlyingDev && pin.inode == mountCleanup.underlyingIno { underlyingSeen = true; continue }; if pin.path == binPath && pin.dev == mountCleanup.mount.dev && pin.inode == mountCleanup.mount.inode { mountedSeen = true }; filtered = append(filtered, pin) }
		if !underlyingSeen || !mountedSeen { return errors.New("both bin creation pins are not retained") }
		if err := checkpointObserverRouteCheckHeldPaths(filtered); err != nil { return err }
	}
	rootInfo, err := os.Lstat(root); if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0711 { return errors.New("local fixture root identity is unavailable") }
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t); if !ok || uint64(rootStat.Dev) != rootDev || rootStat.Ino != rootInode || rootStat.Uid != 0 || rootStat.Nlink < 2 { return errors.New("local fixture root held identity changed") }
	confDir, keyDir, runDir, binDir := filepath.Join(root, "conf"), filepath.Join(root, "signing"), filepath.Join(root, "run"), filepath.Join(root, "bin")
	_, groupID, err := checkpointObserverRouteFixtureGroup()
	if err != nil { return fmt.Errorf("local fixture cleanup group is unavailable: %w", err) }
	if err := checkpointObserverRouteRequireExactNames(root, []string{"bin", "conf", "run", "signing"}); err != nil { return err }
	for _, item := range []struct { path string; mode os.FileMode; gid uint32 }{{confDir, 0750, groupID}, {keyDir, 0700, 0}, {runDir, 0750, groupID}, {binDir, 0711, 0}} { if err := checkpointObserverRouteRequireOwnedDirectory(item.path, item.mode, item.gid); err != nil { return err } }
	if err := checkpointObserverRouteRequireExactNames(confDir, []string{"observer.pub", "policy.json"}); err != nil { return err }
	if err := checkpointObserverRouteRequireExactNames(keyDir, []string{"observer.key"}); err != nil { return err }
	if err := checkpointObserverRouteRequireExactNames(runDir, []string{}); err != nil {
		return err
	}
	if err := checkpointObserverRouteRequireExactNames(binDir, []string{"nodeagent.test"}); err != nil {
		return err
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
		gid  uint32
		max  int64
	}{{filepath.Join(confDir, "observer.pub"), 0640, groupID, 4096}, {filepath.Join(confDir, "policy.json"), 0600, groupID, 64 << 10}, {filepath.Join(keyDir, "observer.key"), 0600, 0, 4096}, {filepath.Join(binDir, "nodeagent.test"), 0555, groupID, 128 << 20}} {
		if err := checkpointObserverRouteRequireOwnedFile(item.path, item.mode, item.gid, item.max); err != nil {
			return err
		}
	}
	for _, file := range []string{filepath.Join(confDir, "observer.pub"), filepath.Join(confDir, "policy.json"), filepath.Join(keyDir, "observer.key"), filepath.Join(binDir, "nodeagent.test")} {
		if err := os.Remove(file); err != nil {
			return err
		}
	}
	if mountCleanup != nil {
		if err := checkpointObserverRouteRequireExactNames(binDir, []string{}); err != nil { return err }; if !checkpointObserverRouteUnderlyingBinCurrent(mountCleanup) || !checkpointObserverRouteTmpfsCurrent(mountCleanup.mount) { return errors.New("bin identity changed before unmount") }
		if err := checkpointObserverRouteTmpfsSettleReferencesUsing(mountCleanup.mount, mountCleanup.clientFD, mountCleanup.mountedRootFD, unix.Close); err != nil { return fmt.Errorf("mounted-bin reference settlement failed: %w", err) }; proof, err := checkpointObserverRouteTmpfsSettledProof(mountCleanup); if err != nil { return err }; if err := checkpointObserverRouteTmpfsUnmountUsing(mountCleanup.mount, proof, unix.Unmount); err != nil { return err }; if !checkpointObserverRouteRevealedUnderlyingBinCurrent(mountCleanup) { return errors.New("unmount did not reveal original empty bin") }
	}
	for _, dir := range []string{confDir, keyDir, runDir, binDir} {
		if err := os.Remove(dir); err != nil {
			return err
		}
	}
	if err := os.Remove(root); err != nil {
		return err
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		return errors.New("local fixture root remains after exact removal")
	}
	return nil
}

type checkpointObserverRouteControlTree struct { root string; rootDev, rootInode uint64; pins []checkpointObserverRouteHeldPath; pending []string; complete, removed bool }
func (tree *checkpointObserverRouteControlTree) cleanup() error {
	var result error
	if len(tree.pending)>0 { result=errors.Join(result,errors.New("new control entry identity unavailable; preserving pending names")) }
	if !tree.removed {
		if tree.complete { result = checkpointObserverRouteRemoveExactLocalTree(tree.root, tree.rootDev, tree.rootInode, tree.pins) } else {
			for i := len(tree.pins)-1; i >= 0; i-- { pin := &tree.pins[i]; info, err := os.Lstat(pin.path); if err == nil && info.Mode()&os.ModeSymlink == 0 && checkpointObserverRouteCheckHeldPaths([]checkpointObserverRouteHeldPath{*pin}) == nil { if stat, ok := info.Sys().(*syscall.Stat_t); ok && uint64(stat.Dev) == pin.dev && stat.Ino == pin.inode { result = errors.Join(result, os.Remove(pin.path)) } else { result = errors.Join(result, errors.New("partial control entry identity changed; preserving name")) } } else if !errors.Is(err, os.ErrNotExist) { result = errors.Join(result, errors.New("partial control entry unavailable or no longer matches original descriptor; preserving name"), err) } }
		}
	}
	result = errors.Join(result, checkpointObserverRouteCloseHeldPaths(tree.pins)); return result
}

func checkpointObserverRouteBuildLocalTreeControl(t *testing.T, suffix string, gid uint32) *checkpointObserverRouteControlTree {
	root, err := os.MkdirTemp("/run", "checkpoint-observer-route-tree-"+suffix+"-"); if err != nil { t.Fatal(err) }
	tree := &checkpointObserverRouteControlTree{root:root,pending:[]string{root}}
	t.Cleanup(func(){ if err := tree.cleanup(); err != nil { t.Errorf("%s exact owned-tree settlement: %v",suffix,err) } })
	rootPin,err:=checkpointObserverRouteCaptureHeldPath(root);if err!=nil{t.Fatalf("retain created control root: %v",err)};tree.pins=append(tree.pins,rootPin);tree.pending=tree.pending[:len(tree.pending)-1];tree.rootDev,tree.rootInode=rootPin.dev,rootPin.inode
	addDir := func(name string, mode os.FileMode, owner uint32) { path:=filepath.Join(root,name); if err:=os.Mkdir(path,0700); err!=nil { t.Fatal(err) }; tree.pending=append(tree.pending,path); pin,err:=checkpointObserverRouteCaptureHeldPath(path); if err!=nil { t.Fatalf("retain new control directory %s: %v",name,err) }; tree.pins=append(tree.pins,pin);tree.pending=tree.pending[:len(tree.pending)-1]; if err:=os.Chown(path,0,int(owner)); err!=nil { t.Fatal(err) }; if err:=os.Chmod(path,mode); err!=nil { t.Fatal(err) }; if err:=checkpointObserverRouteRefreshHeldPath(&tree.pins[len(tree.pins)-1]); err!=nil { t.Fatal(err) } }
	if err:=os.Chmod(root,0711); err!=nil { t.Fatal(err) }; if err:=checkpointObserverRouteRefreshHeldPath(&tree.pins[0]); err!=nil { t.Fatal(err) }
	addDir("conf",0750,gid); addDir("signing",0700,0); addDir("run",0750,gid); addDir("bin",0711,0)
	for _, item := range []struct{name string; data []byte; mode os.FileMode; gid uint32}{{"conf/observer.pub",[]byte("p"),0640,gid},{"conf/policy.json",[]byte("{}"),0600,gid},{"signing/observer.key",[]byte("k"),0600,0},{"bin/nodeagent.test",[]byte("x"),0555,gid}} { pin,err:=checkpointObserverRouteCreateHeldFixtureFile(filepath.Join(root,item.name),item.data,0,item.gid,item.mode); if err!=nil { t.Fatalf("create retained control file %s: %v",item.name,err) }; tree.pins=append(tree.pins,pin) }
	tree.complete=true; return tree
}

func checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {
	_,gid,err:=checkpointObserverRouteFixtureGroup(); if err!=nil { t.Fatal(err) }
	positive:=checkpointObserverRouteBuildLocalTreeControl(t,"positive",gid); if err:=checkpointObserverRouteCheckHeldPaths(positive.pins); err!=nil { t.Fatalf("initial populated known-owned positive rejected: %v",err) }; if err:=checkpointObserverRouteRemoveExactLocalTree(positive.root,positive.rootDev,positive.rootInode,positive.pins); err!=nil { t.Fatalf("initial populated exact-cleanup positive failed: %v",err) }; positive.removed=true; if err:=checkpointObserverRouteCloseHeldPaths(positive.pins); err!=nil { t.Fatalf("initial positive descriptor settlement: %v",err) }
	for _,kind:=range []string{"directory","file","unknown"} {
		tree:=checkpointObserverRouteBuildLocalTreeControl(t,kind,gid); root,pins:=tree.root,tree.pins; original:=append([]checkpointObserverRouteHeldPath(nil),pins...)
		switch kind {
		case "directory":
			path,held:=filepath.Join(root,"conf"),filepath.Join(root,"conf-held"); if err:=os.Rename(path,held); err!=nil { t.Fatal(err) }; tree.pins[1].path=held
			tree.complete=false; tree.pins[5].path=filepath.Join(held,"observer.pub"); tree.pins[6].path=filepath.Join(held,"policy.json")
			if err:=os.Mkdir(path,0700); err!=nil { t.Fatal(err) };tree.pending=append(tree.pending,path);replacement,err:=checkpointObserverRouteCaptureHeldPath(path); if err!=nil { t.Fatal(err) }; tree.pins=append(tree.pins,replacement);tree.pending=tree.pending[:len(tree.pending)-1]; if err:=os.Chown(path,0,int(gid)); err!=nil { t.Fatal(err) }; if err:=os.Chmod(path,0750); err!=nil { t.Fatal(err) }; if err:=checkpointObserverRouteRefreshHeldPath(&tree.pins[len(tree.pins)-1]); err!=nil { t.Fatal(err) }
			for _,item:=range []struct{name string; data []byte; mode os.FileMode}{{"observer.pub",[]byte("p"),0640},{"policy.json",[]byte("{}"),0600}} { pin,err:=checkpointObserverRouteCreateHeldFixtureFile(filepath.Join(path,item.name),item.data,0,gid,item.mode); if err!=nil { t.Fatal(err) }; tree.pins=append(tree.pins,pin) }
		case "file":
			path,held:=filepath.Join(root,"conf","observer.pub"),filepath.Join(root,"conf","observer.pub-held"); if err:=os.Rename(path,held); err!=nil { t.Fatal(err) }; tree.complete=false; tree.pins[5].path=held; pin,err:=checkpointObserverRouteCreateHeldFixtureFile(path,[]byte("p"),0,gid,0640); if err!=nil { t.Fatal(err) }; tree.pins=append(tree.pins,pin)
		case "unknown":
			tree.complete=false; pin,err:=checkpointObserverRouteCreateHeldFixtureFile(filepath.Join(root,"run","unexpected"),[]byte("unknown"),0,gid,0600); if err!=nil { t.Fatal(err) }; tree.pins=append(tree.pins,pin)
		}
		err:=checkpointObserverRouteCheckHeldPaths(original); if kind=="unknown" { err=checkpointObserverRouteRemoveExactLocalTree(root,tree.rootDev,tree.rootInode,original); if err==nil||!strings.Contains(err.Error(),"unexpected") { t.Fatalf("unknown topology missed intended exact-name error: %v",err) } } else if err==nil||!strings.Contains(err.Error(),"held creation-time inode") { t.Fatalf("same-shaped changed-inode %s missed intended custody error: %v",kind,err) }
		if kind=="directory" { info,err:=os.Lstat(filepath.Join(root,"conf-held")); if err!=nil||info.Sys().(*syscall.Stat_t).Ino!=tree.pins[1].inode { t.Fatal("directory substitution did not preserve its creation-time original") } }; if kind=="file" { info,err:=os.Lstat(filepath.Join(root,"conf","observer.pub-held")); if err!=nil||info.Sys().(*syscall.Stat_t).Ino!=tree.pins[5].inode { t.Fatal("file substitution did not preserve its creation-time original") } }
		if kind=="unknown" { path:=filepath.Join(root,"run","unexpected"); content,readErr:=os.ReadFile(path); info,statErr:=os.Lstat(path); if readErr!=nil||statErr!=nil||string(content)!="unknown"||info.Mode()&os.ModeSymlink!=0||info.Sys().(*syscall.Stat_t).Ino!=tree.pins[len(tree.pins)-1].inode { t.Fatal("unknown topology object was not preserved") } }
	}
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS")
}

func TestCheckpointObserverRouteComposedClientChild(t *testing.T) {
	if os.Getenv(checkpointObserverRouteChildEnv) != "client" || os.Geteuid() != 65534 {
		return
	}
	group, _, err := checkpointObserverRouteFixtureGroup()
	if err != nil { t.Fatal(err) }
	clientStage := checkpointLocalObserverStageNone
	localRoot := filepath.Dir(filepath.Dir(os.Getenv(checkpointObserverRouteLocalSocketEnv)))
	config := checkpointLocalObserverRuntimeConfig{
		socketPath: os.Getenv(checkpointObserverRouteLocalSocketEnv), socketDir: filepath.Dir(os.Getenv(checkpointObserverRouteLocalSocketEnv)),
		policyPath: os.Getenv(checkpointObserverRouteLocalPolicyEnv), privatePath: os.Getenv(checkpointObserverRouteLocalKeyEnv),
		publicPath: os.Getenv(checkpointObserverRouteLocalPublicEnv), nodeGroup: group.Name, trustRoot: localRoot, fixtureAnchor: true, fixtureStageSink: func(stage checkpointLocalObserverStage) { clientStage = stage },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	binding, err := routeCheckpointManagedBindingObserver(ctx, os.Geteuid(), func(callCtx context.Context) (CheckpointManagedBinding, error) {
		result, err := checkpointLocalObserverObserveWithConfig(callCtx, config)
		if err != nil {
			return CheckpointManagedBinding{}, err
		}
		return result.Binding, nil
	}, nil)
	if record := checkpointObserverRouteClientFailureRecord(err, binding, clientStage); record != "" { fmt.Printf("REMOTE_OBSERVER_ROUTE_CLIENT %s\n", record); t.Fatalf("fixed signed local managed route did not return the held root binding: err=%v", err) }
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS")
}

func TestCheckpointObserverRouteWorkerChild(t *testing.T) {
	if os.Getenv(checkpointObserverRouteWorkerChildEnv) != "1" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func checkpointObserverRouteParentDeathControl(executable string) (result error) {
	oldSubreaper, err := checkpointObserverRouteGetPrctlInt(unix.PR_GET_CHILD_SUBREAPER)
	if err != nil { return fmt.Errorf("read original child-subreaper state: %w", err) }
	if oldSubreaper != 0 && oldSubreaper != 1 { return errors.New("original child-subreaper readback was not boolean") }
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil { return fmt.Errorf("enable bounded child-subreaper owner: %w", err) }
	var parentPIDFD, probePIDFD = -1, -1
	var parentDone chan error
	parentReaped, probeReaped, probeOwnershipTransferred, probeAckCommitted := true, true, false, false
	var controllerSocket *os.File
	var parentSocket *os.File
	var parent *exec.Cmd
	var parentOutput *checkpointLocalObserverLimitedBuffer
	var nonce string
	defer func() {
		var settlement error
		if parentDone != nil && !parentReaped {
			if probeOwnershipTransferred && parentPIDFD >= 0 { settlement = errors.Join(settlement, unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)) }
			select { case <-parentDone: parentReaped = true; case <-time.After(17*time.Second): settlement = errors.Join(settlement, errors.New("parent-death sacrificial creator Wait/reap is unconfirmed after its fixed self-deadline")) }
		}
		if parentReaped && parentDone != nil {
			if checkpointObserverRouteAcceptLocalReap(parentOutput, nonce, probeAckCommitted) { probeReaped = true }
			if !probeOwnershipTransferred && checkpointObserverRouteCreatorReportsNoProbe(parentOutput, nonce) { probeReaped = true }
		}
		if parentReaped && probeOwnershipTransferred && !probeReaped && probePIDFD >= 0 {
			settlement = errors.Join(settlement, unix.PidfdSendSignal(probePIDFD, syscall.SIGKILL, nil, 0))
			reaped, reapErr := checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)
			if reaped { probeReaped = true }
			settlement = errors.Join(settlement, reapErr)
		}
		if probeOwnershipTransferred && !probeReaped { settlement = errors.Join(settlement, errors.New("transferred original probe identity was not fully reaped")) }
		if probePIDFD >= 0 { fd := probePIDFD; probePIDFD = -1; settlement = errors.Join(settlement, unix.Close(fd)) }
		if parentPIDFD >= 0 { fd := parentPIDFD; parentPIDFD = -1; settlement = errors.Join(settlement, unix.Close(fd)) }
		if controllerSocket != nil { file := controllerSocket; controllerSocket = nil; settlement = errors.Join(settlement, file.Close()) }
		if parentSocket != nil { file := parentSocket; parentSocket = nil; settlement = errors.Join(settlement, file.Close()) }
		if parentReaped && probeReaped {
			if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, uintptr(oldSubreaper), 0, 0, 0); err != nil { settlement = errors.Join(settlement, fmt.Errorf("restore original child-subreaper state: %w", err)) }
			restored, restoreErr := checkpointObserverRouteGetPrctlInt(unix.PR_GET_CHILD_SUBREAPER)
			if restoreErr != nil || restored != oldSubreaper { settlement = errors.Join(settlement, errors.New("original child-subreaper state did not restore exactly"), restoreErr) }
		} else {
			settlement = errors.Join(settlement, errors.New("child-subreaper remains enabled because original child Wait/reap settlement is uncertain"))
		}
		result = errors.Join(result, settlement)
	}()
	gotSubreaper, err := checkpointObserverRouteGetPrctlInt(unix.PR_GET_CHILD_SUBREAPER)
	if err != nil || gotSubreaper != 1 { return errors.Join(errors.New("child-subreaper state did not read back as enabled"), err) }
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil { return fmt.Errorf("create bounded parent/probe custody socketpair: %w", err) }
	controllerSocket = os.NewFile(uintptr(pair[0]), "observer-route-parent-custody")
	parentSocket = os.NewFile(uintptr(pair[1]), "observer-route-parent-custody-child")
	parent = exec.Command(executable, "-test.run=^TestCheckpointObserverRouteParentDeathFixture$", "-test.count=1", "-test.timeout=15s")
	parent.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD, Pdeathsig: syscall.SIGKILL}
	parent.ExtraFiles = []*os.File{parentSocket}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil { return fmt.Errorf("create bounded parent/probe custody nonce: %w", err) }
	nonce = hex.EncodeToString(nonceBytes)
	parent.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C", checkpointObserverRouteChildEnv + "=parent-death-parent", checkpointObserverRouteParentDeathNonceEnv + "=" + nonce}
	parentOutput = &checkpointLocalObserverLimitedBuffer{}
	parent.Stdout, parent.Stderr = parentOutput, parentOutput
	if err := parent.Start(); err != nil { return fmt.Errorf("start bounded parent-death creator: %w", err) }
	parentReaped, probeReaped = false, false
	parentDone = make(chan error, 1)
	go func() { parentDone <- parent.Wait() }()
	if parentPIDFD < 0 || checkpointLocalObserverPidfdTarget(parentPIDFD) != parent.Process.Pid { return errors.New("parent-death creator lacks immediate original pidfd custody") }
	parentSocketFile := parentSocket
	parentSocket = nil
	if err := parentSocketFile.Close(); err != nil { return fmt.Errorf("close controller copy of inherited creator socket: %w", err) }
	controlFD := int(controllerSocket.Fd())
	if err := unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 4}); err != nil { return fmt.Errorf("bound probe custody receive: %w", err) }
	data := make([]byte, 256)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, flags, _, recvErr := unix.Recvmsg(controlFD, data, oob, unix.MSG_CMSG_CLOEXEC)
	var messages []unix.SocketControlMessage
	var receivedFDs []int
	var ancillaryErr error
	if oobn > 0 {
		messages, ancillaryErr = unix.ParseSocketControlMessage(oob[:oobn])
		for index := range messages {
			rights, rightsErr := unix.ParseUnixRights(&messages[index])
			ancillaryErr = errors.Join(ancillaryErr, rightsErr)
			receivedFDs = append(receivedFDs, rights...)
		}
	}
	closeReceived := func() error { var closeErr error; for _, fd := range receivedFDs { closeErr = errors.Join(closeErr, unix.Close(fd)) }; receivedFDs = nil; return closeErr }
	if recvErr != nil || ancillaryErr != nil || flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || n == 0 {
		return errors.Join(errors.New("bounded original probe pidfd handoff failed, malformed or truncated"), recvErr, ancillaryErr, closeReceived())
	}
	if len(messages) != 1 || len(receivedFDs) != 1 {
		var closeErr error
		for _, fd := range receivedFDs { closeErr = errors.Join(closeErr, unix.Close(fd)) }
		receivedFDs = nil
		return errors.Join(errors.New("probe custody handoff did not contain exactly one control message and one original pidfd"), closeErr)
	}
	candidateProbePIDFD := receivedFDs[0]
	fields := strings.Fields(string(data[:n]))
	closeCandidate := func() error { if candidateProbePIDFD < 0 { return nil }; fd := candidateProbePIDFD; candidateProbePIDFD = -1; return unix.Close(fd) }
	if len(fields) != 4 || fields[2] != "READY" || fields[3] != nonce { return errors.Join(errors.New("probe handoff omitted its bounded live-ready identity or fresh nonce"), closeCandidate()) }
	probePID, pidErr := strconv.Atoi(fields[0])
	probeStart, startErr := strconv.ParseUint(fields[1], 10, 64)
	if pidErr != nil || startErr != nil || probePID <= 1 || probeStart == 0 || checkpointLocalObserverPidfdTarget(candidateProbePIDFD) != probePID || checkpointLocalPIDFDAlive(candidateProbePIDFD) != nil { return errors.Join(errors.New("received probe pidfd does not match its live creation-time READY identity"), closeCandidate()) }
	currentStart, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(probePID)), probePID)
	if startErr != nil || currentStart != probeStart || checkpointLocalObserverProcessParent(probePID) != parent.Process.Pid { return errors.Join(errors.New("probe creation identity or parent coupling differs from its live READY record"), closeCandidate()) }
	if err := checkpointObserverRouteCheckProbeIdentity(probePID, parent.Process.Pid, executable); err != nil { return errors.Join(fmt.Errorf("received probe executable, uid/gid or namespace identity differs from its creator: %w", err), closeCandidate()) }
	probePIDFD, probeReaped, probeOwnershipTransferred = candidateProbePIDFD, false, true
	candidateProbePIDFD = -1
	if err := checkpointObserverRouteBoundSocketSend(controlFD); err != nil { return fmt.Errorf("bound original probe ACK send: %w", err) }
	ackN, ackErr := unix.SendmsgN(controlFD, []byte("ACK "+nonce), nil, nil, 0)
	if ackErr != nil || ackN != len("ACK "+nonce) { return errors.Join(errors.New("original probe pidfd custody acknowledgement was incomplete; outer retains bounded reap ownership"), ackErr) }
	if err := unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil { return fmt.Errorf("bound original probe custody COMMIT receive: %w", err) }
	commit := make([]byte, 64)
	commitN, commitControlN, commitFlags, _, commitErr := unix.Recvmsg(controlFD, commit, nil, 0)
	if commitErr != nil || commitFlags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || commitControlN != 0 || string(commit[:commitN]) != "COMMIT "+nonce { return errors.Join(errors.New("original probe custody COMMIT was absent, truncated or mismatched; transaction remains failure-only cleanup"), commitErr) }
	probeAckCommitted = true
	if err := unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0); err != nil { return fmt.Errorf("signal only the original parent pidfd: %w", err) }
	select {
	case parentErr := <-parentDone:
		parentReaped = true
		if checkpointObserverRouteAcceptLocalReap(parentOutput, nonce, probeAckCommitted) { probeReaped = true }
		if !probeOwnershipTransferred {
			if probeReaped {
				probeReaped = true
			} else {
				return errors.New("creator exited without transferred probe custody or exact local Wait/reap marker")
			}
		}
		var exitErr *exec.ExitError
		if !errors.As(parentErr, &exitErr) { return errors.New("parent-death creator exited without signal status") }
		status, statusOK := exitErr.Sys().(syscall.WaitStatus)
		if !statusOK || !status.Signaled() || status.Signal() != syscall.SIGKILL { return errors.New("parent-death creator did not exit by the exact held SIGKILL") }
	case <-time.After(3*time.Second): return errors.New("parent-death creator did not Wait/reap within its fixed deadline")
	}
	if checkpointLocalPIDFDAlive(parentPIDFD) == nil { return errors.New("parent-death creator remained live after Wait") }
	if !probeReaped {
		reaped, err := checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)
		if reaped { probeReaped = true }
		if err != nil { return err }
	}
	return nil
}

func checkpointObserverRouteCreatorLocallyReaped(output *checkpointLocalObserverLimitedBuffer, nonce string) bool {
	if output == nil || nonce == "" { return false }
	parentText, overflow := output.snapshot()
	if overflow { return false }
	marker := "CHECKPOINT_OBSERVER_ROUTE_PROBE_LOCAL_REAPED "+nonce+" STATUS="
	return strings.Count(string(parentText), marker) == 1 &&
		(strings.Contains(string(parentText), marker+"SIGKILL\n") || strings.Contains(string(parentText), marker+"OTHER\n"))
}

func checkpointObserverRouteCreatorReportsNoProbe(output *checkpointLocalObserverLimitedBuffer, nonce string) bool {
	if output == nil || nonce == "" { return false }
	data, overflow := output.snapshot()
	return !overflow && strings.Count(string(data), "CHECKPOINT_OBSERVER_ROUTE_NO_CHILD "+nonce) == 1
}

func checkpointObserverRouteAcceptLocalReap(output *checkpointLocalObserverLimitedBuffer, nonce string, committed bool) bool {
	return !committed && checkpointObserverRouteCreatorLocallyReaped(output, nonce)
}

func checkpointObserverRouteBoundSocketSend(fd int) error {
	if fd < 0 { return errors.New("bounded socket sender lacks an owned descriptor") }
	return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 2})
}

func checkpointObserverRouteCheckProbeIdentity(pid, parentPID int, executable string) error {
	if pid <= 1 || parentPID <= 1 || executable == "" { return errors.New("probe identity lacks positive PIDs or executable") }
	processPath := filepath.Join("/proc", strconv.Itoa(pid))
	parentPath := filepath.Join("/proc", strconv.Itoa(parentPID))
	processInfo, err := os.Stat(processPath)
	if err != nil { return fmt.Errorf("stat probe process owner: %w", err) }
	parentInfo, err := os.Stat(parentPath)
	if err != nil { return fmt.Errorf("stat creator process owner: %w", err) }
	processStat, processOK := processInfo.Sys().(*syscall.Stat_t)
	parentStat, parentOK := parentInfo.Sys().(*syscall.Stat_t)
	if !processOK || !parentOK || processStat.Uid != parentStat.Uid || processStat.Gid != parentStat.Gid || processStat.Uid != uint32(os.Getuid()) || processStat.Gid != uint32(os.Getgid()) {
		return errors.New("probe and creator real uid/gid identities do not match the current owner")
	}
	executableInfo, err := os.Stat(executable)
	if err != nil { return fmt.Errorf("stat expected probe executable: %w", err) }
	processExecutable, err := os.Stat(filepath.Join(processPath, "exe"))
	if err != nil { return fmt.Errorf("stat held probe executable identity: %w", err) }
	if !os.SameFile(executableInfo, processExecutable) { return errors.New("probe executable inode differs from the fixed test executable") }
	for _, namespace := range []string{"pid", "user", "mnt"} {
		creatorNS, creatorErr := os.Stat(filepath.Join(parentPath, "ns", namespace))
		probeNS, probeErr := os.Stat(filepath.Join(processPath, "ns", namespace))
		if creatorErr != nil || probeErr != nil || !os.SameFile(creatorNS, probeNS) { return errors.Join(fmt.Errorf("probe %s namespace differs from its creator", namespace), creatorErr, probeErr) }
	}
	return nil
}

func checkpointObserverRouteGetPrctlInt(option int) (int, error) {
	var value int32
	if err := unix.Prctl(option, uintptr(unsafe.Pointer(&value)), 0, 0, 0); err != nil { return 0, err }
	runtime.KeepAlive(&value)
	return int(value), nil
}

func TestCheckpointObserverRouteParentDeathFixture(t *testing.T) {
	if os.Getenv(checkpointObserverRouteChildEnv) != "parent-death-parent" { return }
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	controlFD := 3
	defer func() { fd := controlFD; controlFD = -1; if fd >= 0 { if err := unix.Close(fd); err != nil { t.Errorf("inherited parent control socket close failed: %v", err) } } }()
	executable, err := os.Executable()
	if err != nil { fmt.Printf("CHECKPOINT_OBSERVER_ROUTE_NO_CHILD %s\n", os.Getenv(checkpointObserverRouteParentDeathNonceEnv)); t.Fatal("parent-death probe executable is unavailable") }
	probe := exec.Command(executable, "-test.run=^TestCheckpointObserverRouteParentDeathProbe$", "-test.count=1", "-test.timeout=7s")
	probePIDFD := -1
	probe.SysProcAttr = &syscall.SysProcAttr{PidFD: &probePIDFD, Pdeathsig: syscall.SIGKILL}
	probe.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", checkpointObserverRouteChildEnv + "=parent-death-probe"}
	probeOutput := &checkpointLocalObserverLimitedBuffer{}
	probe.Stdout, probe.Stderr = probeOutput, probeOutput
	if err := probe.Start(); err != nil { fmt.Printf("CHECKPOINT_OBSERVER_ROUTE_NO_CHILD %s\n", os.Getenv(checkpointObserverRouteParentDeathNonceEnv)); t.Fatal("parent-death probe could not start") }
	probeHandedOff, probeWaited := false, false
	probeDone := make(chan error, 1)
	go func() { probeDone <- probe.Wait() }()
	defer func() {
		if !probeHandedOff && !probeWaited {
			if probePIDFD >= 0 {
				if err := unix.PidfdSendSignal(probePIDFD, syscall.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) { t.Errorf("creator-owned probe pidfd KILL failed: %v", err) }
			}
			select {
			case waitErr := <-probeDone:
				probeWaited = true
				sigkill := false
				var exitErr *exec.ExitError
				if errors.As(waitErr, &exitErr) { if status, ok := exitErr.Sys().(syscall.WaitStatus); ok { sigkill = status.Signaled() && status.Signal() == syscall.SIGKILL } }
				if !sigkill { t.Errorf("creator-owned probe did not exit with exact bounded parent-death SIGKILL: %v", waitErr) }
				statusName := "OTHER"
				if sigkill { statusName = "SIGKILL" }
				fmt.Printf("CHECKPOINT_OBSERVER_ROUTE_PROBE_LOCAL_REAPED %s STATUS=%s\n", os.Getenv(checkpointObserverRouteParentDeathNonceEnv), statusName)
			case <-time.After(8 * time.Second):
				t.Errorf("creator-owned probe Wait/reap remains unconfirmed after bounded self-deadline")
			}
		}
		if probePIDFD >= 0 { fd := probePIDFD; probePIDFD = -1; if err := unix.Close(fd); err != nil { t.Errorf("creator probe pidfd settlement failed: %v", err) } }
	}()
	if probePIDFD < 0 || checkpointLocalObserverPidfdTarget(probePIDFD) != probe.Process.Pid { t.Fatal("probe creator did not retain atomic original pidfd custody") }
	if err := checkpointObserverRouteBoundSocketSend(controlFD); err != nil { t.Fatalf("bound original probe custody socket send: %v", err) }
	line, readyErr := checkpointObserverRouteWaitReadyLine(probeOutput, 3*time.Second)
	if readyErr != nil { t.Fatal(readyErr) }
	{
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != "CHECKPOINT_OBSERVER_ROUTE_PROBE_READY" || fields[1] != strconv.Itoa(probe.Process.Pid) || fields[3] != strconv.Itoa(os.Getpid()) || fields[4] != "PDEATHSIG=9" { t.Fatal("probe live-positive READY identity did not bind its original creator") }
		start, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil || start == 0 { t.Fatal("probe READY omitted its creation start identity") }
		if err := checkpointObserverRouteCheckProbeIdentity(probe.Process.Pid, os.Getpid(), executable); err != nil { t.Fatalf("probe executable, uid/gid or namespace identity differs from its creator: %v", err) }
		nonce := os.Getenv(checkpointObserverRouteParentDeathNonceEnv)
		if len(nonce) != 48 || strings.Trim(nonce, "0123456789abcdef") != "" { t.Fatal("parent-death nonce is unavailable or malformed") }
		if err := unix.SetsockoptTimeval(controlFD, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2}); err != nil { t.Fatalf("bound original probe custody acknowledgement: %v", err) }
		handoff := []byte(fmt.Sprintf("%d %d READY %s", probe.Process.Pid, start, nonce))
		if sent, err := unix.SendmsgN(controlFD, handoff, unix.UnixRights(probePIDFD), nil, 0); err != nil || sent != len(handoff) { t.Fatalf("transfer original probe pidfd custody was partial: sent=%d err=%v", sent, err) }
		ack, ackControl := make([]byte, 64), make([]byte, unix.CmsgSpace(4))
		ackN, ackControlN, ackFlags, _, ackErr := unix.Recvmsg(controlFD, ack, ackControl, 0)
		var ackAncillaryErr error
		var ackRights []int
		if ackControlN > 0 {
			messages, parseErr := unix.ParseSocketControlMessage(ackControl[:ackControlN])
			ackAncillaryErr = errors.Join(ackAncillaryErr, parseErr)
			for index := range messages { rights, rightsErr := unix.ParseUnixRights(&messages[index]); ackAncillaryErr = errors.Join(ackAncillaryErr, rightsErr); ackRights = append(ackRights, rights...) }
		}
		for _, fd := range ackRights { ackAncillaryErr = errors.Join(ackAncillaryErr, unix.Close(fd)) }
		if ackErr != nil || ackAncillaryErr != nil || ackFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || ackControlN != 0 || string(ack[:ackN]) != "ACK "+nonce { t.Fatalf("original probe custody ACK was absent, truncated or mismatched: %v", errors.Join(ackErr, ackAncillaryErr)) }
		probeHandedOff = true
		fd := probePIDFD
		probePIDFD = -1
		if err := unix.Close(fd); err != nil { t.Fatalf("creator pidfd handoff close failed: %v", err) }
		commit := []byte("COMMIT "+nonce)
		if sent, err := unix.SendmsgN(controlFD, commit, nil, nil, 0); err != nil || sent != len(commit) { t.Fatalf("original probe custody COMMIT was partial: sent=%d err=%v", sent, err) }
	}
	select {}
}

func checkpointObserverRouteWaitReadyLine(output *checkpointLocalObserverLimitedBuffer, timeout time.Duration) (string, error) {
	if output == nil || timeout <= 0 { return "", errors.New("probe READY reader lacks bounded capture or deadline") }
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, overflow := output.snapshot()
		if overflow { return "", errors.New("probe READY capture exceeded its fixed bound") }
		if newline := strings.IndexByte(string(data), '\n'); newline >= 0 { return strings.TrimSuffix(string(data[:newline]), "\r"), nil }
		time.Sleep(10*time.Millisecond)
	}
	return "", errors.New("probe did not complete its bounded live-positive identity handshake")
}

func TestCheckpointObserverRouteParentDeathProbe(t *testing.T) {
	if os.Getenv(checkpointObserverRouteChildEnv) != "parent-death-probe" { return }
	pdeath, pdeathErr := checkpointObserverRouteGetPrctlInt(unix.PR_GET_PDEATHSIG)
	start, startErr := checkpointProcessStart("/proc/self", os.Getpid())
	if pdeathErr != nil || pdeath != int(syscall.SIGKILL) || startErr != nil || start == 0 { t.Fatal("probe self-deadline or parent-death signal is not active") }
	fmt.Printf("CHECKPOINT_OBSERVER_ROUTE_PROBE_READY %d %d %d PDEATHSIG=%d\n", os.Getpid(), start, os.Getppid(), pdeath)
	for { time.Sleep(time.Hour) }
}

func checkpointLocalObserverProcessParent(pid int) int {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil { return -1 }
	close := strings.LastIndexByte(string(raw), ')')
	if close < 0 { return -1 }
	fields := strings.Fields(string(raw[close+1:]))
	if len(fields) < 2 { return -1 }
	parent, err := strconv.Atoi(fields[1])
	if err != nil { return -1 }
	return parent
}

func checkpointObserverRouteWaitExactChild(pidfd int, timeout time.Duration) (bool, error) {
	if pidfd < 0 || timeout <= 0 { return false, errors.New("exact child reaper lacks an original pidfd or deadline") }
	pid := checkpointLocalObserverPidfdTarget(pidfd)
	if pid <= 1 { return false, errors.New("exact child pidfd has no positive target") }
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var originalInfo unix.Siginfo
		if err := unix.Waitid(unix.P_PIDFD, pidfd, &originalInfo, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil); err != nil {
			if errors.Is(err, unix.EINTR) { continue }
			return false, fmt.Errorf("waitid WNOWAIT on the original adopted-child pidfd: %w", err)
		}
		if originalInfo.Signo == 0 {
			time.Sleep(10*time.Millisecond)
			continue
		}
		if originalInfo.Signo != int32(syscall.SIGCHLD) { return false, errors.New("original pidfd waitable status was not SIGCHLD") }
		var status syscall.WaitStatus
		waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.EINTR) { continue }
		if err != nil { return false, fmt.Errorf("actual surviving subreaper Wait4(%d): %w", pid, err) }
		if waited == pid {
			if !status.Signaled() || status.Signal() != syscall.SIGKILL { return true, errors.New("adopted original probe was reaped without its exact parent-death SIGKILL") }
			return true, nil
		}
		if waited != 0 { return false, errors.New("subreaper consumed a different child while reaping the exact probe") }
		return false, errors.New("original pidfd reported a waitable child but exact Wait4 did not consume its creation PID")
	}
	return false, errors.New("actual surviving subreaper did not fully reap the exact probe before deadline")
}

func TestCheckpointObserverRouteComposedBrokerChild(t *testing.T) {
	if os.Getenv(checkpointObserverRouteChildEnv) != "broker" {
		return
	}
	if os.Getpid() <= 1 || os.Geteuid() != 0 {
		t.Fatal("local observer broker must be a root child process distinct from namespace init")
	}
	workerPID, err := strconv.Atoi(os.Getenv(checkpointObserverRouteWorkerChildEnv + "_PID"))
	if err != nil || workerPID <= 1 {
		t.Fatal("held root worker PID is unavailable to broker child")
	}
	config := checkpointObserverRouteComposedServerConfig(t, workerPID)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- checkpointLocalObserverRunWithConfig(ctx, config) }()
	if err := checkpointObserverRouteWaitForSocket(config.socketPath, 3*time.Second); err != nil {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		t.Fatalf("root broker child socket did not become ready: %v", err)
	}
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS")
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("root broker child listener failed: %v", err)
	}
}

func checkpointObserverRouteComposedServerConfig(t *testing.T, workerPID int) checkpointLocalObserverRuntimeConfig {
	t.Helper()
	group, _, err := checkpointObserverRouteFixtureGroup()
	if err != nil { t.Fatal(err) }
	worker, err := checkpointLocalObserverOpenCurrent(workerPID)
	if err != nil || worker.uid != 0 || worker.pid <= 1 {
		if worker != nil { worker.close() }
		t.Fatal("composed local broker cannot hold the exact root worker")
	}
	workerStart, workerCgroup := worker.start, worker.cgroup
	worker.close()
	plan, association := managedBindingFixture(); plan.Placement.PhysicalIdentity = "GPU-00000000-0000-0000-0000-000000000019"
	association.Identity.PID, association.Custody.PID = workerPID, workerPID
	association.Identity.ProcessStartTicks, association.Custody.ProcessStartTicks = workerStart, workerStart
	association.ControlGroup = workerCgroup
	association.Invocation = "0123456789abcdef0123456789abcdef"
	placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: "synthetic fixture inventory"}
	pin := &PinnedCheckpointLaunchPlan{plan: plan, contentSHA256: sha256.Sum256([]byte("composed fixed source-only route fixture"))}
	bridgeConfig := checkpointHostGPUBridgeRuntimeConfig{socketPath: os.Getenv(checkpointObserverRouteHostSocketEnv), trustPath: filepath.Join(filepath.Dir(os.Getenv(checkpointObserverRouteHostConfigEnv)), "trust.json"), publicKeyPath: filepath.Join(filepath.Dir(os.Getenv(checkpointObserverRouteHostConfigEnv)), "observer.pub"), discoverDevices: func(context.Context) ([]checkpointGPUDevice, error) {
		return []checkpointGPUDevice{{UUID: plan.Placement.PhysicalIdentity, PCI: "0000:19:00.0"}}, nil
	}}
	source := checkpointManagedObservationSource{
		openPlan: func(context.Context) (*PinnedCheckpointLaunchPlan, error) { return pin, nil },
		validatePlan: func(value *PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error) { return value.Spec(), nil },
		recheckPlan: func(context.Context, *PinnedCheckpointLaunchPlan) error { return nil },
		openStore: func(CheckpointLaunchPlan) (*CheckpointCustodyStore, error) { return &CheckpointCustodyStore{}, nil },
		associate: func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) { return association, nil },
		alias: func(context.Context, CheckpointLaunchEndpoint, string) (string, error) { return plan.Alias, nil },
		placement: func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) { return placement, nil },
		namespaceRoute: func(context.Context, int) (bool, error) { return true, nil },
		nestedFootprint: func(ctx context.Context, pid int, start uint64, currentPlan CheckpointLaunchPlan, currentPlacement CheckpointDevicePlacement) (int64, int64, error) {
			return observeNestedManagedCheckpointFootprintUsing(ctx, pid, start, currentPlan, currentPlacement, func(callCtx context.Context, worker int, workerStart uint64, hostPlan CheckpointLaunchPlan, hostPlacement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {
				return observeCheckpointHostGPUAttributionLocalObserverUsing(callCtx, worker, workerStart, hostPlan, hostPlacement, bridgeConfig)
			})
		},
		footprint: func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) { return 0, 0, errors.New("composed fixture must not use local direct inventory") },
		readArgv: func(int) ([]string, error) { return managedCheckpointExpectedArgv(plan) },
	}
	localRoot := os.Getenv(checkpointObserverRouteLocalRootEnv)
	return checkpointLocalObserverRuntimeConfig{socketPath: os.Getenv(checkpointObserverRouteLocalSocketEnv), socketDir: filepath.Dir(os.Getenv(checkpointObserverRouteLocalSocketEnv)),
		policyPath: os.Getenv(checkpointObserverRouteLocalPolicyEnv), privatePath: os.Getenv(checkpointObserverRouteLocalKeyEnv), publicPath: os.Getenv(checkpointObserverRouteLocalPublicEnv),
		nodeGroup: group.Name, trustRoot: localRoot, fixtureAnchor: true,
		fixtureStageSink: func(stage checkpointLocalObserverStage) { fmt.Printf("REMOTE_OBSERVER_ROUTE_BROKER stage=%s\n", checkpointLocalObserverStageCode(stage)) },
		collect: func(ctx context.Context) (CheckpointManagedBinding, error) { var records [2]string; recordCount, sinkOverflow := 0, false; binding, err, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, func(record string) { if recordCount >= len(records) { sinkOverflow = true; return }; records[recordCount] = record; recordCount++ }, observeCheckpointManagedBindingLinux); for _, record := range checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid) { fmt.Println(record) }; return binding, err }}
}

func checkpointObserverRouteComposedPID1(t *testing.T) {
	localRootRawFD := 3
	defer func() { if closeErr := checkpointObserverRouteCloseFD(&localRootRawFD); closeErr != nil { t.Errorf("inherited raw local-root descriptor settlement failed: %v", closeErr) } }()
	failRawLocalRoot := func(cause error) { t.Helper(); t.Fatalf("PID1 inherited local-root custody failed: %v", errors.Join(cause, checkpointObserverRouteCloseFD(&localRootRawFD))) }

	if os.Getpid() != 1 || os.Geteuid() != 0 {
		failRawLocalRoot(errors.New("composed fixture did not enter the exact root PID-namespace init"))
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		failRawLocalRoot(fmt.Errorf("make exact test mount namespace private: %w", err))
	}
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		failRawLocalRoot(fmt.Errorf("mount the bounded fixture PID namespace proc view: %w", err))
	}
	root := os.Getenv(checkpointObserverRouteRootEnv)
	localRoot := os.Getenv(checkpointObserverRouteLocalRootEnv)
	if root == "" || filepath.Clean(root) != root || localRoot == "" || filepath.Clean(localRoot) != localRoot || localRoot == root || strings.HasPrefix(localRoot, root+string(os.PathSeparator)) {
		failRawLocalRoot(errors.New("composed private root is unavailable"))
	}
	localRootFD, err := strconv.Atoi(os.Getenv(checkpointObserverRouteLocalRootFDEnv))
	if err != nil || localRootFD != localRootRawFD { failRawLocalRoot(errors.New("PID1 did not receive the exact inherited outer local-root descriptor")) }
	localRootPin, err := checkpointObserverRouteAdoptLocalRootFD(&localRootRawFD, localRoot)
	if err != nil { failRawLocalRoot(fmt.Errorf("inherited outer local-root creation custody is invalid: %w", err)) }
	localPins := []checkpointObserverRouteHeldPath{localRootPin}
	localRootPin.fd = -1
	var mountedBin *checkpointObserverRouteTmpfsMount
	localCleanupUncertain := false
	localTreeCleaned := false
	defer func() { if closeErr := checkpointObserverRouteTmpfsClose(mountedBin); closeErr != nil { localCleanupUncertain = true } }()
	defer func() {
		if closeErr := checkpointObserverRouteCloseHeldPaths(localPins); closeErr != nil {
			localCleanupUncertain = true
			t.Errorf("local original creation-custody descriptor settlement failed: %v", closeErr)
		}
		if !localTreeCleaned { localCleanupUncertain = true }
	}()
	_, groupID, err := checkpointObserverRouteFixtureGroup()
	if err != nil { t.Fatal(err) }
	confDir, keyDir, runDir := filepath.Join(localRoot, "conf"), filepath.Join(localRoot, "signing"), filepath.Join(localRoot, "run")
	binDir := filepath.Join(localRoot, "bin")
	for _, dir := range []string{confDir, keyDir, runDir, binDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatalf("create exact composed local observer directory: %v", err)
		}
		pin, err := checkpointObserverRouteCaptureHeldPath(dir)
		if err != nil { t.Fatalf("retain each directory's identity at its creation site: %v", err) }
		localPins = append(localPins, pin)
		pin.fd = -1
	}
	for _, item := range []struct {
		path string
		gid  uint32
		mode os.FileMode
	}{{confDir, groupID, 0750}, {keyDir, 0, 0700}, {runDir, groupID, 0750}, {binDir, 0, 0711}} {
		if err := os.Chown(item.path, 0, int(item.gid)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(item.path, item.mode); err != nil {
			t.Fatal(err)
		}
		for index := range localPins { if localPins[index].path == item.path { if err := checkpointObserverRouteRefreshHeldPath(&localPins[index]); err != nil { t.Fatal(err) } } }
	}
	workerExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	clientExecutable := filepath.Join(binDir, "nodeagent.test")
	mountedBin, err = checkpointObserverRouteMountPrivateExecutableBin(localRoot, binDir, localPins[0].fd, localRootPin.dev, localRootPin.inode, localPins[4].fd, localPins[4].dev, localPins[4].inode)
	var mountedRootPin checkpointObserverRouteHeldPath; mountedRootPinIndex := -1; if err == nil { mountedRootPin, err = checkpointObserverRouteCaptureHeldPath(binDir) }; if err == nil { localPins = append(localPins, mountedRootPin); mountedRootPinIndex = len(localPins)-1; err = checkpointObserverRouteTmpfsTrackReference(mountedBin); mountedRootPin.fd = -1 }
	var clientDigest string
	var clientPin checkpointObserverRouteHeldPath
	if err == nil { clientDigest, clientPin, err = checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID) }
	if err != nil {
		t.Fatalf("publish exact held client test executable for unprivileged traversal: %v", err)
	}
	localPins = append(localPins, clientPin); clientPinIndex := len(localPins)-1; if err := checkpointObserverRouteTmpfsTrackReference(mountedBin); err != nil { t.Fatalf("could not retain mounted client path custody: %v", err) }
	clientPin.fd = -1
	self, err := checkpointLocalObserverOpenCurrent(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	localCgroup := self.cgroup
	localPolicy := checkpointLocalObserverPolicy{Version: checkpointLocalObserverVersion, PeerUID: 65534, PeerGID: groupID, ExecutablePath: clientExecutable, ExecutableSHA256: clientDigest, ControlGroup: localCgroup}
	if self.uid != 0 || self.namespace.NamespaceType != uint64(unix.CLONE_NEWPID) {
		self.close()
		t.Fatal("local root collector and root worker are not in the same held PID namespace and cgroup")
	}
	self.close()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := json.Marshal(localPolicy)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct { path string; data []byte; gid uint32; mode os.FileMode }{
		{os.Getenv(checkpointObserverRouteLocalPolicyEnv), policyBytes, groupID, 0600},
		{os.Getenv(checkpointObserverRouteLocalKeyEnv), private, 0, 0600},
		{os.Getenv(checkpointObserverRouteLocalPublicEnv), public, groupID, 0640},
	} {
		pin, err := checkpointObserverRouteCreateHeldFixtureFile(item.path, item.data, 0, item.gid, item.mode)
		if err != nil { t.Fatalf("create and retain original local authority file: %v", err) }
		localPins = append(localPins, pin)
		pin.fd = -1
	}
	worker := exec.Command(workerExecutable, "-test.run=^TestCheckpointObserverRouteWorkerChild$", "-test.count=1", "-test.timeout=30s")
	workerPIDFD := -1
	worker.SysProcAttr = &syscall.SysProcAttr{PidFD: &workerPIDFD, Pdeathsig: syscall.SIGKILL}
	worker.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", checkpointObserverRouteWorkerChildEnv + "=1"}
	if err := worker.Start(); err != nil { t.Fatal(err) }
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Wait() }()
	workerReaped := false
	defer func() {
		if !workerReaped && workerPIDFD >= 0 {
			if _, stopErr := checkpointObserverRouteStopAndWait(workerPIDFD, workerDone, 3*time.Second); stopErr != nil { localCleanupUncertain = true; t.Errorf("composed worker cleanup/reap is unconfirmed: %v", stopErr) } else { workerReaped = true }
		}
		if !workerReaped { localCleanupUncertain = true }
		if closeErr := checkpointObserverRouteCloseFD(&workerPIDFD); closeErr != nil { localCleanupUncertain = true; t.Errorf("composed worker pidfd close failed: %v", closeErr) }
	}()
	if workerPIDFD < 0 || checkpointLocalObserverPidfdTarget(workerPIDFD) != worker.Process.Pid { t.Fatal("composed worker did not retain its original pidfd") }
	workerPID := worker.Process.Pid
	workerStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(workerPID)), workerPID)
	if err != nil || workerStart == 0 || checkpointLocalPIDFDAlive(workerPIDFD) != nil { t.Fatal("composed root worker currentness could not be held") }
	workerIdentity, err := checkpointLocalObserverOpenCurrent(workerPID)
	if err != nil || workerIdentity.uid != 0 { t.Fatal("composed worker does not have exact root-owned process identity") }
	workerCgroup := workerIdentity.cgroup
	workerIdentity.close()
	if workerCgroup != localCgroup { t.Fatal("created worker does not share the pinned local collector cgroup") }

	serverConfig := checkpointObserverRouteComposedServerConfig(t, workerPID)
	broker := exec.Command(workerExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedBrokerChild$", "-test.count=1", "-test.timeout=90s")
	brokerPIDFD := -1
	broker.SysProcAttr = &syscall.SysProcAttr{PidFD: &brokerPIDFD, Pdeathsig: syscall.SIGKILL}
	broker.Env = []string{"PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C",
		checkpointObserverRouteChildEnv + "=broker", checkpointObserverRouteWorkerChildEnv + "_PID=" + strconv.Itoa(workerPID),
		checkpointObserverRouteRootEnv + "=" + os.Getenv(checkpointObserverRouteRootEnv),
		checkpointObserverRouteHostSocketEnv + "=" + os.Getenv(checkpointObserverRouteHostSocketEnv),
		checkpointObserverRouteHostConfigEnv + "=" + os.Getenv(checkpointObserverRouteHostConfigEnv),
		checkpointObserverRouteHostKeyEnv + "=" + os.Getenv(checkpointObserverRouteHostKeyEnv),
		checkpointObserverRouteLocalRootEnv + "=" + localRoot,
		checkpointObserverRouteLocalSocketEnv + "=" + serverConfig.socketPath,
		checkpointObserverRouteLocalPolicyEnv + "=" + serverConfig.policyPath,
		checkpointObserverRouteLocalKeyEnv + "=" + serverConfig.privatePath,
		checkpointObserverRouteLocalPublicEnv + "=" + serverConfig.publicPath}
	brokerOutput := &checkpointLocalObserverLimitedBuffer{}
	broker.Stdout, broker.Stderr = brokerOutput, brokerOutput
	if err := broker.Start(); err != nil {
		_ = unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0)
		t.Fatalf("could not start a held root broker child: %v", err)
	}
	brokerDone := make(chan error, 1)
	go func() { brokerDone <- broker.Wait() }()
	brokerReaped := false
	defer func() {
		if !brokerReaped && brokerPIDFD >= 0 {
			if _, stopErr := checkpointObserverRouteStopAndWait(brokerPIDFD, brokerDone, 3*time.Second); stopErr != nil {
				localCleanupUncertain = true
				t.Errorf("root broker child cleanup/reap is unconfirmed: %v", stopErr)
			} else {
				brokerReaped = true
			}
		}
		if !brokerReaped { localCleanupUncertain = true }
		if closeErr := checkpointObserverRouteCloseFD(&brokerPIDFD); closeErr != nil { localCleanupUncertain = true; t.Errorf("root broker pidfd close failed: %v", closeErr) }
	}()
	if brokerPIDFD < 0 || broker.Process.Pid <= 1 || checkpointLocalObserverPidfdTarget(brokerPIDFD) != broker.Process.Pid {
		t.Fatal("local observer broker is not a held child PID greater than one")
	}
	if err := checkpointObserverRouteWaitForSocket(serverConfig.socketPath, 3*time.Second); err != nil {
		t.Fatalf("composed root broker child did not bind its local observer socket: %v", err)
	}
	if err := checkpointObserverRouteWaitForOutputMarker(brokerOutput, brokerPIDFD, "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS", 3*time.Second); err != nil {
		data, _ := brokerOutput.snapshot()
		t.Fatalf("held root broker child readiness marker was not delivered exactly once: %v (%s)", err, boundedLocalObserverText(data))
	}
	brokerIdentity, err := checkpointLocalObserverOpenCurrent(broker.Process.Pid)
	if err != nil || brokerIdentity.uid != 0 || brokerIdentity.namespace.NamespaceType != uint64(unix.CLONE_NEWPID) || brokerIdentity.pid <= 1 || checkpointLocalPIDFDAlive(brokerPIDFD) != nil {
		if brokerIdentity != nil { brokerIdentity.close() }
		t.Fatal("local broker child identity was not held as root PID greater than one")
	}
	brokerIdentity.close()
	client := exec.Command(clientExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedClientChild$", "-test.count=1", "-test.timeout=15s")
	var clientPIDFD int
	clientPIDFD = -1
	client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: groupID, NoSetGroups: true}, PidFD: &clientPIDFD, Pdeathsig: syscall.SIGKILL}
	client.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C", "LC_ALL=C", checkpointObserverRouteChildEnv + "=client",
		checkpointObserverRouteLocalSocketEnv + "=" + serverConfig.socketPath, checkpointObserverRouteLocalPolicyEnv + "=" + serverConfig.policyPath,
		checkpointObserverRouteLocalKeyEnv + "=" + serverConfig.privatePath, checkpointObserverRouteLocalPublicEnv + "=" + serverConfig.publicPath}
	clientOutput := &checkpointLocalObserverLimitedBuffer{}
	client.Stdout, client.Stderr = clientOutput, clientOutput
	if err := client.Start(); err != nil {
		_ = unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0)
		t.Fatalf("could not start exact unprivileged signed client: %v", err)
	}
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Wait() }()
	clientReaped := false
	defer func() {
		if !clientReaped && clientPIDFD >= 0 {
			if _, stopErr := checkpointObserverRouteStopAndWait(clientPIDFD, clientDone, 3*time.Second); stopErr != nil {
				localCleanupUncertain = true
				t.Errorf("unprivileged client cleanup/reap is unconfirmed: %v", stopErr)
			} else { clientReaped = true }
		}
		if !clientReaped { localCleanupUncertain = true }
		if closeErr := checkpointObserverRouteCloseFD(&clientPIDFD); closeErr != nil { localCleanupUncertain = true; t.Errorf("unprivileged client pidfd close failed: %v", closeErr) }
	}()
	if clientPIDFD < 0 || checkpointLocalObserverPidfdTarget(clientPIDFD) != client.Process.Pid || checkpointLocalPIDFDAlive(clientPIDFD) != nil {
			_ = unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0)
		t.Fatalf("unprivileged client has no original atomic pidfd identity")
	}
	select {
	case err := <-clientDone:
		clientReaped = true
		clientData, clientOverflow := clientOutput.snapshot(); brokerData, brokerOverflow := brokerOutput.snapshot()
		if err != nil || clientOverflow || checkpointLocalPIDFDAlive(clientPIDFD) == nil || strings.Count(string(clientData), "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS") != 1 {
			_ = unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0)
			clientRecord, brokerRecord, phaseSuffix, clientSource := checkpointObserverRoutePID1FailureRecord(clientData, clientOverflow, brokerData, brokerOverflow); t.Fatalf("REMOTE_OBSERVER_ROUTE_PID1 client=%s broker=%s%s%s", clientRecord, brokerRecord, phaseSuffix, clientSource)
		}
	case <-time.After(18 * time.Second):
		t.Fatal("unprivileged signed route client exceeded its fixed deadline")
	}
	if closeErr := checkpointObserverRouteCloseFD(&clientPIDFD); closeErr != nil { localCleanupUncertain = true; t.Fatalf("unprivileged client original pidfd settlement failed: %v", closeErr) }
	if err := unix.PidfdSendSignal(brokerPIDFD, syscall.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		t.Fatalf("could not signal exact held root broker child: %v", err)
	}
	select {
	case err := <-brokerDone:
		brokerReaped = true
		brokerData, brokerOverflow := brokerOutput.snapshot()
		if err != nil || brokerOverflow {
			t.Fatalf("local broker child cleanup failed after actual signed route: %v (%s)", err, boundedLocalObserverText(brokerData))
		}
	case <-time.After(3 * time.Second):
		_ = unix.PidfdSendSignal(brokerPIDFD, syscall.SIGKILL, nil, 0)
		t.Fatal("local broker child reap is uncertain; preserving fixture state")
	}
	if checkpointLocalPIDFDAlive(brokerPIDFD) == nil {
		t.Fatal("local broker child remained live after confirmed Wait")
	}
	if _, err := os.Lstat(serverConfig.socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("local signed observer socket remains or is uncertain")
	}
	if closeErr := checkpointObserverRouteCloseFD(&brokerPIDFD); closeErr != nil { localCleanupUncertain = true; t.Fatalf("local broker original pidfd settlement failed: %v", closeErr) }
	if err := unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		t.Fatalf("could not signal exact held composed worker pidfd: %v", err)
	}
	select {
	case err := <-workerDone:
		workerReaped = true
		if err == nil {
			t.Fatal("composed worker exited cleanly without the exact fixture signal")
		}
	case <-time.After(3 * time.Second):
		_ = unix.PidfdSendSignal(workerPIDFD, syscall.SIGKILL, nil, 0)
		t.Fatal("composed worker did not reap under its original pidfd")
	}
	if checkpointLocalPIDFDAlive(workerPIDFD) == nil {
		t.Fatal("composed worker remained live after exact pidfd cleanup")
	}
	if closeErr := checkpointObserverRouteCloseFD(&workerPIDFD); closeErr != nil { localCleanupUncertain = true; t.Fatalf("composed worker pidfd settlement failed: %v", closeErr) }
	if localCleanupUncertain { t.Fatal("a child owner is uncertain; exact local-tree removal is suppressed") }
	mountedCleanup := &checkpointObserverRouteMountedCleanup{mount: mountedBin, rootPath: localRoot, rootFD: localPins[0].fd, rootDev: localPins[0].dev, rootIno: localPins[0].inode, underlyingPath: binDir, underlyingFD: localPins[4].fd, underlyingDev: localPins[4].dev, underlyingIno: localPins[4].inode, clientFD: &localPins[clientPinIndex].fd, mountedRootFD: &localPins[mountedRootPinIndex].fd, childrenClear: true}
	if err := checkpointObserverRouteRemoveExactLocalTree(localRoot, localRootPin.dev, localRootPin.inode, localPins, mountedCleanup); err != nil {
		t.Fatalf("could not remove exact local fixture using its live creation-time descriptors: %v", err)
	}
	if closeErr := checkpointObserverRouteCloseHeldPaths(localPins); closeErr != nil { localCleanupUncertain = true; t.Fatalf("local held-path settlement failed before cleanup success: %v", closeErr) }
	if localCleanupUncertain { t.Fatal("local fixture custody settlement is uncertain; cleanup success is suppressed") }
	localTreeCleaned = true
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS")
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS")
}

func checkpointObserverRouteWaitForSocket(socket string, timeout time.Duration) error {
	if socket == "" || filepath.Clean(socket) != socket {
		return errors.New("route fixture socket path is invalid")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(socket)
		if err == nil && info.Mode()&os.ModeSocket != 0 && info.Mode().Perm() == 0660 {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return errors.New("route fixture socket did not appear within its fixed bound")
}

func checkpointObserverRouteStopAndWait(pidfd int, done <-chan error, timeout time.Duration) (error, error) {
	if pidfd < 0 || timeout <= 0 {
		return nil, errors.New("child cleanup has no original pidfd or finite deadline")
	}
	if err := unix.PidfdSendSignal(pidfd, syscall.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return nil, fmt.Errorf("TERM through original child pidfd: %w", err)
	}
	select {
	case waitErr := <-done:
		return waitErr, nil
	case <-time.After(timeout):
	}
	if err := unix.PidfdSendSignal(pidfd, syscall.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return nil, fmt.Errorf("KILL through original child pidfd: %w", err)
	}
	select {
	case waitErr := <-done:
		return waitErr, nil
	case <-time.After(timeout):
		return nil, errors.New("child Wait did not confirm reap after bounded TERM/KILL escalation")
	}
}

func checkpointObserverRouteWaitForOutputMarker(output *checkpointLocalObserverLimitedBuffer, pidfd int, marker string, timeout time.Duration) error {
	if output == nil || pidfd < 0 || marker == "" || timeout <= 0 {
		return errors.New("readiness control lacks a bounded buffer, original pidfd, marker, or deadline")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, overflow := output.snapshot()
		count := strings.Count(string(data), marker)
		if overflow { return errors.New("bounded child output overflowed before readiness") }
		if count > 1 { return errors.New("child readiness marker was duplicated") }
		if count == 1 {
			time.Sleep(40 * time.Millisecond)
			stable, overflow := output.snapshot()
			if overflow || strings.Count(string(stable), marker) != 1 { return errors.New("child readiness marker was not stable and exact-once") }
			if err := checkpointLocalPIDFDAlive(pidfd); err != nil { return errors.New("child exited before bounded readiness confirmation") }
			return nil
		}
		if err := checkpointLocalPIDFDAlive(pidfd); err != nil { return errors.New("child exited before readiness marker delivery") }
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("child readiness marker missed its fixed deadline")
}

func checkpointLocalObserverKernelFixtureBody(t *testing.T, abruptParent bool) {
	if os.Getenv(checkpointLocalObserverKernelOptIn) != "1" {
		t.Fatalf("tagged kernel fixture requires explicit %s=1 admission", checkpointLocalObserverKernelOptIn)
	}
	group, err := user.LookupGroup("vram-governor")
	if err != nil {
		t.Fatalf("existing production vram-governor group is required; no account is created: %v", err)
	}
	groupNumber, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupNumber == 0 {
		t.Fatalf("existing vram-governor group has an invalid numeric GID %q", group.Gid)
	}
	groupID := uint32(groupNumber)
	wrongGID := checkpointLocalObserverFixtureWrongGID(groupID)
	root, err := os.MkdirTemp("", "checkpoint-local-observer-fixture-")
	if err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		t.Fatal(err)
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootStat.Uid != 0 || rootInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("private fixture root is not root-owned: %s", root)
	}
	var workerUnit, replacementUnit, unrelatedUnit, brokerUnit *checkpointLocalObserverFixtureUnit
	workerReaped, replacementReaped, unrelatedReaped, brokerStopped := true, true, true, true
	parentAliasCleanupRequired, parentAliasCleanupConfirmed := false, true
	var serverResult chan error
	serverStopped, allScenariosPassed := true, false
	stopBroker := func() error {
		if brokerUnit == nil || brokerStopped {
			return nil
		}
		if err := checkpointLocalObserverStopFixtureUnit(brokerUnit); err != nil {
			return err
		}
		brokerUnit.owned = false
		brokerStopped = true
		return nil
	}
	defer func() {
		var cleanupErr error
		if abruptParent {
			t.Errorf("outer-parent fixture ended before coordinator-confirmed cleanup; preserving exact private root %s", root)
			return
		}
		if serverResult != nil && !serverStopped {
			select {
			case err := <-serverResult:
				serverStopped = err == nil
				if err != nil {
					cleanupErr = errors.Join(cleanupErr, fmt.Errorf("broker service cleanup: %w", err))
				}
			case <-time.After(3 * time.Second):
				cleanupErr = errors.Join(cleanupErr, errors.New("broker service cleanup timed out"))
			}
		}
		if brokerUnit != nil && !brokerStopped {
			if err := checkpointLocalObserverStopFixtureUnit(brokerUnit); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("broker fixture cleanup: %w", err))
			} else {
				brokerStopped = true
			}
		}
		if workerUnit != nil && !workerReaped {
			if err := checkpointLocalObserverStopFixtureUnit(workerUnit); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("original worker fixture cleanup: %w", err))
			} else {
				workerReaped = true
			}
		}
		if replacementUnit != nil && !replacementReaped {
			if err := checkpointLocalObserverStopFixtureUnit(replacementUnit); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("replacement worker fixture cleanup: %w", err))
			} else {
				replacementReaped = true
			}
		}
		if unrelatedUnit != nil && !unrelatedReaped {
			if err := checkpointLocalObserverStopFixtureUnit(unrelatedUnit); err != nil {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("unrelated control fixture cleanup: %w", err))
			} else {
				unrelatedReaped = true
			}
		}
		socketPath := filepath.Join(root, "run", "observer.sock")
		_, socketErr := os.Lstat(socketPath)
		if !serverStopped || !brokerStopped || !errors.Is(socketErr, os.ErrNotExist) || !workerReaped || !replacementReaped || !unrelatedReaped {
			t.Errorf("fixture cleanup uncertainty (%v); preserving exact private root %s", cleanupErr, root)
			return
		}
		currentRoot, statErr := os.Lstat(root)
		if statErr != nil {
			t.Errorf("fixture root became unavailable; preserving %s", root)
			return
		}
		currentStat, statOK := currentRoot.Sys().(*syscall.Stat_t)
		if !statOK || currentStat.Dev != rootStat.Dev || currentStat.Ino != rootStat.Ino || currentRoot.Mode()&os.ModeSymlink != 0 {
			t.Errorf("private fixture root identity changed; preserving %s", root)
			return
		}
		if parentAliasCleanupRequired && !parentAliasCleanupConfirmed {
			t.Errorf("parent-substitution alias identity or absence is uncertain; preserving exact private root %s", root)
			return
		}
		if parentAliasCleanupRequired {
			if _, err := os.Lstat(filepath.Join(root, "parent-substitution")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("parent-substitution alias remains or is uncertain; preserving exact private root %s", root)
				return
			}
		}
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("could not remove exact private fixture root %s: %v", root, err)
			return
		}
		checkpointLocalObserverCloseFixtureUnit(workerUnit)
		checkpointLocalObserverCloseFixtureUnit(replacementUnit)
		checkpointLocalObserverCloseFixtureUnit(unrelatedUnit)
		checkpointLocalObserverCloseFixtureUnit(brokerUnit)
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__")
		if allScenariosPassed {
			fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_POSITIVE__")
		}
	}()
	// Only this exact private fixture root becomes searchable by the child;
	// its sticky /tmp parent and all descendant directory identities are held.
	if err := os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	confDir := filepath.Join(root, "conf")
	keyDir := filepath.Join(root, "signing")
	socketDir := filepath.Join(root, "run")
	for _, dir := range []string{confDir, keyDir, socketDir} {
		if err := os.Mkdir(dir, 0750); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(dir, 0, int(groupID)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chown(keyDir, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(confDir, 0, int(groupID)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(socketDir, 0, int(groupID)); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		mode os.FileMode
	}{{confDir, 0750}, {keyDir, 0700}, {socketDir, 0750}} {
		if err := os.Chmod(item.path, item.mode); err != nil {
			t.Fatal(err)
		}
	}

	self, err := checkpointLocalObserverOpenCurrent(os.Getpid())
	if err != nil {
		t.Fatalf("hold root test peer: %v", err)
	}
	policy := checkpointLocalObserverPolicy{Version: checkpointLocalObserverVersion, PeerUID: 65534, PeerGID: groupID, ExecutablePath: self.exe, ExecutableSHA256: strings.ToLower(self.exeSHA256), ControlGroup: self.cgroup}
	self.close()
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(confDir, "policy.json")
	privatePath := filepath.Join(keyDir, "observer.key")
	publicPath := filepath.Join(confDir, "observer.pub")
	socketPath := filepath.Join(socketDir, "observer.sock")
	writeFixtureFile(t, policyPath, policyBytes, 0, 0, 0600)
	writeFixtureFile(t, privatePath, private, 0, 0, 0600)
	writeFixtureFile(t, publicPath, public, 0, groupID, 0640)
	permissionConfig := checkpointLocalObserverRuntimeConfig{publicPath: publicPath, nodeGroup: group.Name, trustRoot: root, fixtureAnchor: true}
	if output := checkpointLocalObserverKernelRunClientMode(t, root, permissionConfig, 0, "public-key-read-positive", 65534, groupID); strings.Count(output, "__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_READ_POSITIVE__") != 1 {
		t.Fatalf("search-only trust root rejected the unprivileged public-key read: %s", boundedLocalObserverText([]byte(output)))
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__")
	permissionDenied := "__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_PERMISSION_DENIED__"
	func() {
		defer func() {
			if err := os.Chmod(root, 0711); err != nil {
				t.Errorf("restore exact private fixture root mode: %v", err)
			}
		}()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		if output := checkpointLocalObserverKernelRunClientMode(t, root, permissionConfig, 0, "public-key-permission-denied", 65534, groupID); strings.Count(output, permissionDenied) != 1 {
			t.Fatal("missing trust-root search permission was not denied exactly once")
		}
	}()
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_ROOT_SEARCH_DENIED__")
	func() {
		defer func() {
			if err := os.Chown(publicPath, 0, int(groupID)); err != nil {
				t.Errorf("restore exact public-key group: %v", err)
			}
			if err := os.Chmod(publicPath, 0640); err != nil {
				t.Errorf("restore exact public-key mode: %v", err)
			}
		}()
		if err := os.Chown(publicPath, 0, int(wrongGID)); err != nil {
			t.Fatal(err)
		}
		if output := checkpointLocalObserverKernelRunClientMode(t, root, permissionConfig, 0, "public-key-permission-denied", 65534, groupID); strings.Count(output, permissionDenied) != 1 {
			t.Fatal("wrong public-key group was not denied exactly once")
		}
	}()
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_GROUP_DENIED__")
	func() {
		defer func() {
			if err := os.Chmod(publicPath, 0640); err != nil {
				t.Errorf("restore exact public-key mode: %v", err)
			}
		}()
		if err := os.Chmod(publicPath, 0600); err != nil {
			t.Fatal(err)
		}
		if output := checkpointLocalObserverKernelRunClientMode(t, root, permissionConfig, 0, "public-key-permission-denied", 65534, groupID); strings.Count(output, permissionDenied) != 1 {
			t.Fatal("inaccessible public-key mode was not denied exactly once")
		}
	}()
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_MODE_DENIED__")
	parentAliasCleanupRequired = true
	parentAliasCleanupConfirmed = false
	const aliasName = "parent-substitution"
	alias := filepath.Join(root, aliasName)
	if _, err := os.Lstat(alias); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("parent-substitution alias path was not absent before creation; preserving exact private root %s", root)
	}
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Lstat(alias)
	if err != nil {
		t.Fatalf("could not pin created parent-substitution symlink; preserving exact private root %s", root)
	}
	aliasStat, ok := aliasInfo.Sys().(*syscall.Stat_t)
	if !ok || aliasInfo.Mode()&os.ModeSymlink == 0 || aliasInfo.Mode()&os.ModeType != os.ModeSymlink || aliasStat.Uid != 0 || aliasStat.Gid != rootStat.Gid || aliasStat.Nlink != 1 {
		t.Fatalf("created parent-substitution alias has unexpected type/owner/link identity; preserving exact private root %s", root)
	}
	aliasTarget, err := os.Readlink(alias)
	if err != nil || aliasTarget != root {
		t.Fatalf("created parent-substitution alias does not target the pinned root; preserving exact private root %s", root)
	}
	parentOutput := checkpointLocalObserverKernelRunClientMode(t, alias, permissionConfig, 0, "public-key-permission-denied", 65534, groupID)
	if err := checkpointLocalObserverRemovePinnedParentAlias(root, rootStat, aliasStat); err != nil {
		t.Fatalf("could not remove only the rechecked parent-substitution alias; preserving exact private root %s: %v", root, err)
	}
	parentAliasCleanupConfirmed = true
	if strings.Count(parentOutput, "__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_PERMISSION_DENIED__") != 1 {
		t.Fatal("symlink-substituted trust-root parent was not denied exactly once")
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_SUBSTITUTION_DENIED__")
	workerReaped = false
	workerUnit, err = checkpointLocalObserverStartFixtureUnit(t, "worker", root, group.Name, 0)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedReaped = false
	unrelatedUnit, err = checkpointLocalObserverStartFixtureUnit(t, "worker", root, group.Name, 0)
	if err != nil {
		t.Fatal(err)
	}
	workerPID := workerUnit.pid
	worker, err := checkpointLocalObserverOpenCurrent(workerPID)
	if err != nil {
		t.Fatalf("root worker did not start with a held pidfd: %v", err)
	}
	if worker.uid != 0 {
		worker.close()
		t.Fatal("kernel fixture worker is not root-owned")
	}
	worker.close()
	config := checkpointLocalObserverRuntimeConfig{socketPath: socketPath, socketDir: socketDir, policyPath: policyPath, privatePath: privatePath, publicPath: publicPath, nodeGroup: group.Name, trustRoot: root, fixtureAnchor: true}
	config.fixturePayloadMutator = func(payload *checkpointLocalObserverPayload) (string, error) {
		// These private CPU controls alter only a signed fixture response; they do
		// not alter Linux namespaces or provide production association evidence.
		phase, phaseErr := checkpointLocalObserverKernelReadPhase(root)
		if phaseErr != nil || phase == "" {
			return "", phaseErr
		}
		switch phase {
		case "identity-substitution":
			payload.Caller.ExecutableSHA256 = strings.Repeat("b", 64)
			return "identity", nil
		case "namespace-substitution":
			payload.Worker.PIDNamespaceInode++
			return "namespace", nil
		default:
			return "", fmt.Errorf("unknown fixture mutation phase %q", phase)
		}
	}
	config.fixtureMutationResult = func(kind string, signed bool) error {
		if kind == "identity" && signed {
			return checkpointLocalObserverKernelWriteMarker(root, "identity-substitution.result", "identity signed\n")
		}
		if kind == "namespace" && !signed {
			return checkpointLocalObserverKernelWriteMarker(root, "namespace-substitution.result", "sign rejected\n")
		}
		return fmt.Errorf("fixture signer reached unexpected %s mutation result signed=%t", kind, signed)
	}
	brokerStopped = false
	brokerUnit, err = checkpointLocalObserverStartFixtureUnit(t, "server", root, group.Name, workerPID)
	if err != nil {
		t.Fatal(err)
	}
	if brokerUnit.cgroup == workerUnit.cgroup || unrelatedUnit.cgroup == workerUnit.cgroup || unrelatedUnit.cgroup == brokerUnit.cgroup {
		t.Fatal("root broker, worker, and unrelated helper must occupy distinct transient cgroups")
	}
	serverResult = make(chan error, 1)
	serverStopped = false
	waiterBrokerObservation := *brokerUnit // immutable ownership snapshot; pidfd remains borrowed until wait completes
	go func() { serverResult <- checkpointLocalObserverWaitFixtureUnit(&waiterBrokerObservation) }()
	if err := checkpointLocalObserverWaitSocket(socketPath, 3*time.Second); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	if marker, err := os.ReadFile(filepath.Join(root, "broker-capability.marker")); err != nil || string(marker) != "CAP_SYS_PTRACE_ONLY_ROOT_VRAM_GROUP_NNP\n" {
		_ = stopBroker()
		t.Fatal("tagged broker did not assert the exact production capability/group posture")
	}
	if err := checkpointLocalObserverAssertEffectiveBrokerUnit(brokerUnit, groupID); err != nil {
		_ = stopBroker()
		t.Fatalf("independent observer did not confirm effective broker syscall/capability posture: %v", err)
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_BROKER_CAPABILITY_POSTURE__")
	for index := 0; index < 2; index++ {
		output := checkpointLocalObserverKernelRunClient(t, root, config, workerPID, 65534, groupID)
		if !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_CLIENT_POSITIVE__") {
			_ = stopBroker()
			t.Fatalf("client %d did not produce an authenticated positive response", index+1)
		}
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_IPC_POSITIVE__")
	unrelated, err := checkpointLocalObserverOpenCurrent(unrelatedUnit.pid)
	if err != nil {
		_ = stopBroker()
		t.Fatalf("unrelated root child did not survive observer requests: %v", err)
	}
	if err := checkpointLocalPIDFDAlive(unrelated.pidfd); err != nil {
		unrelated.close()
		_ = stopBroker()
		t.Fatal("unrelated root child exited during observation")
	}
	unrelated.close()
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_UNRELATED_SURVIVED__")
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "wrong-peer", 65533, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_WRONG_PEER_DENIED__") {
		_ = stopBroker()
		t.Fatal("wrong-UID peer unexpectedly received a root-signed response")
	}
	peerDenial, err := os.ReadFile(filepath.Join(root, "peer-denied-uid.marker"))
	if err != nil || string(peerDenial) != fmt.Sprintf("SO_PEERCRED_POLICY_DENIED uid=65533 gid=%d\n", groupID) {
		_ = stopBroker()
		t.Fatal("root broker did not independently observe and deny the exact wrong-UID SO_PEERCRED")
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_PEER_DENIED__")
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "wrong-gid", 65534, wrongGID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_WRONG_GID_DENIED__") {
		_ = stopBroker()
		t.Fatal("wrong-GID peer unexpectedly received a root-signed response")
	}
	peerDenial, err = os.ReadFile(filepath.Join(root, "peer-denied-gid.marker"))
	if err != nil || string(peerDenial) != fmt.Sprintf("SO_PEERCRED_POLICY_DENIED uid=65534 gid=%d\n", wrongGID) {
		_ = stopBroker()
		t.Fatal("root broker did not independently observe and deny the exact wrong-GID SO_PEERCRED")
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_GID_DENIED__")
	for _, role := range []string{"wrong-key", "wrong-nonce"} {
		output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, role, 65534, groupID)
		marker := "__CHECKPOINT_LOCAL_OBSERVER_WRONG_KEY_DENIED__"
		if role == "wrong-nonce" {
			marker = "__CHECKPOINT_LOCAL_OBSERVER_WRONG_NONCE_DENIED__"
		}
		if !strings.Contains(output, marker) {
			_ = stopBroker()
			t.Fatalf("signed response was not rejected by the explicit %s control", role)
		}
		if role == "wrong-key" {
			fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_KEY_DENIED__")
		} else {
			fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_NONCE_DENIED__")
		}
	}
	if err := checkpointLocalObserverKernelWriteMarker(root, "identity-substitution.phase", "identity-substitution\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "identity-substitution", 65534, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_IDENTITY_SUBSTITUTION_DENIED__") {
		_ = stopBroker()
		t.Fatal("client accepted a root-signed caller executable identity substitution")
	}
	if err := checkpointLocalObserverKernelRequireMutationMarker(root, "identity-substitution.result", "identity signed\n"); err != nil {
		_ = stopBroker()
		t.Fatalf("identity substitution did not reach a signed positive-response control: %v", err)
	}
	if err := checkpointLocalObserverKernelRemoveMarker(root, "identity-substitution.phase", "identity-substitution\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	if err := checkpointLocalObserverKernelWriteMarker(root, "namespace-substitution.phase", "namespace-substitution\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "namespace-substitution", 65534, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_NAMESPACE_SUBSTITUTION_DENIED__") {
		_ = stopBroker()
		t.Fatal("root broker signed a substituted worker namespace")
	}
	if err := checkpointLocalObserverKernelRequireMutationMarker(root, "namespace-substitution.result", "sign rejected\n"); err != nil {
		_ = stopBroker()
		t.Fatalf("namespace substitution was not rejected by the signer: %v", err)
	}
	if err := checkpointLocalObserverKernelRemoveMarker(root, "namespace-substitution.phase", "namespace-substitution\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_IDENTITY_SUBSTITUTION_DENIED__")
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_NAMESPACE_SUBSTITUTION_DENIED__")

	if err := checkpointLocalObserverStopFixtureUnit(workerUnit); err != nil {
		t.Fatalf("owned original worker unit failed to stop/reap exactly: %v", err)
	}
	workerUnit.owned = false
	workerReaped = true
	if err := checkpointLocalObserverKernelWriteMarker(root, "worker-exit.phase", "worker-exit\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "worker-exit", 65534, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_WORKER_EXIT_DENIED__") {
		_ = stopBroker()
		t.Fatal("broker signed an association after the fixed worker exited")
	}
	if err := checkpointLocalObserverKernelRequireMutationMarker(root, "worker-exit-denied.marker", "FIXED_WORKER_EXIT_NOT_CURRENT\n"); err != nil {
		_ = stopBroker()
		t.Fatalf("worker-exit control lacked its distinct server denial marker: %v", err)
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_EXIT_DENIED__")
	if err := checkpointLocalObserverKernelRemoveMarker(root, "worker-exit.phase", "worker-exit\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	replacementReaped = false
	replacementUnit, err = checkpointLocalObserverStartFixtureUnit(t, "worker", root, group.Name, 0)
	if err != nil || replacementUnit.pid == workerPID || replacementUnit.start == workerUnit.start {
		t.Fatalf("could not create an independently held replacement worker after original reap: replacement=%+v err=%v", replacementUnit, err)
	}
	replacement, err := checkpointLocalObserverOpenCurrent(replacementUnit.pid)
	if err != nil || replacement.uid != 0 || checkpointLocalPIDFDAlive(replacement.pidfd) != nil {
		if replacement != nil {
			replacement.close()
		}
		t.Fatalf("replacement worker was not live and root-owned: %v", err)
	}
	replacement.close()
	if err := checkpointLocalObserverKernelWriteMarker(root, "worker-replaced.phase", "worker-replaced\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}

	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "worker-replaced", 65534, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_WORKER_REPLACED_DENIED__") {
		_ = stopBroker()
		t.Fatal("replacement worker did not fail closed against the stale fixed-worker association")
	}
	if err := checkpointLocalObserverKernelRequireMutationMarker(root, "replacement-worker-denied.marker", "FIXED_WORKER_REPLACEMENT_NOT_CURRENT\n"); err != nil {
		_ = stopBroker()
		t.Fatalf("replacement control lacked its distinct server denial marker: %v", err)
	}
	if err := checkpointLocalObserverKernelRemoveMarker(root, "worker-replaced.phase", "worker-replaced\n"); err != nil {
		_ = stopBroker()
		t.Fatal(err)
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_REPLACED_DENIED__")
	if err := checkpointLocalObserverKernelSubstitutePublicKey(root, publicPath, groupID); err != nil {
		_ = stopBroker()
		t.Fatalf("prepare exact root public-key substitution control: %v", err)
	}
	if output := checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, "key-substitution", 65534, groupID); !strings.Contains(output, "__CHECKPOINT_LOCAL_OBSERVER_KEY_SUBSTITUTION_DENIED__") {
		_ = stopBroker()
		t.Fatal("substituted root public-key path did not fail closed")
	}
	keyMarker, err := os.ReadFile(filepath.Join(root, "key-substitution-denied.marker"))
	if err != nil || string(keyMarker) != "HELD_ROOT_KEY_PATH_SUBSTITUTION_DENIED\n" {
		_ = stopBroker()
		t.Fatal("broker did not independently record held root-key path substitution")
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_KEY_SUBSTITUTION_DENIED__")
	unrelatedAgain, err := checkpointLocalObserverOpenCurrent(unrelatedUnit.pid)
	if err != nil || unrelatedAgain.uid != 0 || checkpointLocalPIDFDAlive(unrelatedAgain.pidfd) != nil {
		if unrelatedAgain != nil {
			unrelatedAgain.close()
		}
		_ = stopBroker()
		t.Fatalf("unrelated fixture child did not survive all observer scenarios: %v", err)
	}
	unrelatedAgain.close()
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_UNRELATED_SURVIVED_ALL__")
	if abruptParent {
		allScenariosPassed = true
		checkpointLocalObserverKernelArmParentDeathCoordinator(t, root, rootStat, workerUnit, replacementUnit, unrelatedUnit, brokerUnit)
		os.Exit(checkpointLocalObserverParentExit)
	}
	if err := stopBroker(); err != nil {
		t.Fatalf("broker unit failed to stop/reap exactly: %v", err)
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatalf("root broker did not stop cleanly: %v", err)
		}
		serverStopped = true
	case <-time.After(3 * time.Second):
		t.Fatal("root broker did not stop within its fixture bound")
	}
	if _, err := os.Lstat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned socket cleanup was not confirmed; preserving fixture: %v", err)
	}
	allScenariosPassed = true
}

type checkpointLocalObserverParentUnit struct {
	Role          string `json:"role"`
	Name          string `json:"name"`
	PID           int    `json:"pid"`
	Start         uint64 `json:"start"`
	StartedMonoNS int64  `json:"started_monotonic_ns"`
	Invocation    string `json:"invocation"`
	Cgroup        string `json:"cgroup"`
}

type checkpointLocalObserverParentDeathConfig struct {
	Version        int                                  `json:"version"`
	Nonce          string                               `json:"nonce"`
	Root           string                               `json:"root"`
	RootDev        uint64                               `json:"root_dev"`
	RootIno        uint64                               `json:"root_ino"`
	ReportDir      string                               `json:"report_dir"`
	ReportDev      uint64                               `json:"report_dev"`
	ReportIno      uint64                               `json:"report_ino"`
	ReportName     string                               `json:"report_name"`
	ParentPID      int                                  `json:"parent_pid"`
	ParentStart    uint64                               `json:"parent_start"`
	SentinelPID    int                                  `json:"sentinel_pid"`
	SentinelStart  uint64                               `json:"sentinel_start"`
	SentinelCgroup string                               `json:"sentinel_cgroup"`
	Units          [4]checkpointLocalObserverParentUnit `json:"units"`
}

type checkpointLocalObserverParentDeathReport struct {
	Version              int       `json:"version"`
	Nonce                string    `json:"nonce"`
	ParentPID            int       `json:"parent_pid"`
	ParentStart          uint64    `json:"parent_start"`
	ExpectedParentExit   int       `json:"expected_parent_exit"`
	ParentDeathObserved  bool      `json:"parent_death_observed"`
	PostDeathLiveUnits   int       `json:"post_death_live_units"`
	OriginalWorkerExited bool      `json:"original_worker_exited"`
	UnitsAbsent          [4]bool   `json:"units_absent"`
	SentinelSurvived     bool      `json:"sentinel_survived"`
	SentinelExited       bool      `json:"sentinel_exited"`
	RootRemoved          bool      `json:"root_removed"`
	SentinelPID          int       `json:"sentinel_pid"`
	SentinelStart        uint64    `json:"sentinel_start"`
	SentinelCgroup       string    `json:"sentinel_cgroup"`
	MaxLiveUnitAgeMs     int64     `json:"max_live_unit_age_ms"`
	UnitRoles            [4]string `json:"unit_roles"`
	UnitNames            [4]string `json:"unit_names"`
}

func checkpointLocalObserverRemovePinnedParentAlias(root string, rootPin, aliasPin *syscall.Stat_t) (result error) {
	const aliasName = "parent-substitution"
	if root == "" || rootPin == nil || aliasPin == nil || rootPin.Uid != 0 || aliasPin.Uid != 0 || aliasPin.Nlink != 1 || aliasPin.Mode&syscall.S_IFMT != syscall.S_IFLNK {
		return errors.New("parent-substitution cleanup lacks exact root and symlink pins")
	}
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("could not hold exact private root for alias cleanup")
	}
	defer func() { result = errors.Join(result, unix.Close(rootFD)) }()
	checkRoot := func() error {
		var held unix.Stat_t
		if err := unix.Fstat(rootFD, &held); err != nil || held.Dev != uint64(rootPin.Dev) || held.Ino != rootPin.Ino || held.Uid != rootPin.Uid || held.Gid != rootPin.Gid || held.Mode&syscall.S_IFMT != syscall.S_IFDIR {
			return errors.New("held parent directory identity changed before alias removal")
		}
		named, err := os.Lstat(root)
		if err != nil || !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || named.Mode().Perm() != 0711 {
			return errors.New("private root path changed before alias removal")
		}
		namedStat, ok := named.Sys().(*syscall.Stat_t)
		if !ok || namedStat.Dev != rootPin.Dev || namedStat.Ino != rootPin.Ino || namedStat.Uid != rootPin.Uid || namedStat.Gid != rootPin.Gid {
			return errors.New("private root path no longer names its pinned parent")
		}
		return nil
	}
	checkAlias := func() error {
		var current unix.Stat_t
		if err := unix.Fstatat(rootFD, aliasName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return errors.New("parent-substitution alias is unavailable or replaced")
		}
		if current.Dev != uint64(aliasPin.Dev) || current.Ino != aliasPin.Ino || current.Uid != aliasPin.Uid || current.Gid != aliasPin.Gid || current.Nlink != aliasPin.Nlink || current.Mode&syscall.S_IFMT != syscall.S_IFLNK {
			return errors.New("parent-substitution alias identity changed; replacement will not be removed")
		}
		var target [4096]byte
		n, err := unix.Readlinkat(rootFD, aliasName, target[:])
		if err != nil || n <= 0 || n >= len(target) || string(target[:n]) != root {
			return errors.New("parent-substitution alias link target changed; path will not be removed")
		}
		return nil
	}
	if err := checkRoot(); err != nil {
		return err
	}
	if err := checkAlias(); err != nil {
		return err
	}
	if err := checkRoot(); err != nil {
		return err
	}
	if err := checkAlias(); err != nil {
		return err
	}
	if err := unix.Unlinkat(rootFD, aliasName, 0); err != nil {
		return errors.New("single exact parent-substitution alias removal failed")
	}
	var after unix.Stat_t
	if err := unix.Fstatat(rootFD, aliasName, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("parent-substitution alias absence was not confirmed after removal")
	}
	if _, err := os.Lstat(filepath.Join(root, aliasName)); !errors.Is(err, os.ErrNotExist) {
		return errors.New("parent-substitution alias remains or path absence is uncertain")
	}
	return nil
}

func TestCheckpointLocalObserverKernelSentinel(t *testing.T) {
	if os.Getenv(checkpointLocalObserverParentMode) != "sentinel" {
		t.Skip("private outer-parent sentinel helper")
	}
	finished := make(chan os.Signal, 1)
	signal.Notify(finished, syscall.SIGTERM)
	defer signal.Stop(finished)
	select {
	case <-time.After(165 * time.Second):
	case <-finished:
	}
}

func TestCheckpointLocalObserverKernelParentDeathCoordinator(t *testing.T) {
	if os.Getenv(checkpointLocalObserverParentMode) != "coordinator" {
		t.Skip("private outer-parent coordinator helper")
	}
	checkpointLocalObserverKernelRunParentDeathCoordinator(t)
}

func checkpointLocalObserverKernelOuterParentDeath(t *testing.T) {
	t.Helper()
	reportDir, err := os.MkdirTemp("", "checkpoint-local-observer-parent-report-")
	if err != nil {
		t.Fatal("could not create private outer-parent report directory")
	}
	if err := os.Chmod(reportDir, 0700); err != nil {
		t.Fatal("could not pin private outer-parent report directory")
	}
	reportInfo, err := os.Lstat(reportDir)
	if err != nil {
		t.Fatal("could not inspect private outer-parent report directory")
	}
	reportStat, ok := reportInfo.Sys().(*syscall.Stat_t)
	if !ok || reportInfo.Mode()&os.ModeSymlink != 0 || !reportInfo.IsDir() || reportStat.Uid != 0 || reportInfo.Mode().Perm() != 0700 {
		t.Fatal("outer-parent report directory is not a pinned root-private directory")
	}
	reportFD, err := os.Open(reportDir)
	if err != nil {
		t.Fatal("could not hold private outer-parent report directory")
	}
	reportFDStat, err := reportFD.Stat()
	if err != nil || !os.SameFile(reportInfo, reportFDStat) {
		_ = reportFD.Close()
		t.Fatal("outer-parent report directory descriptor does not match its path")
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		_ = reportFD.Close()
		t.Fatal("could not pin the current tagged test executable")
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		_ = reportFD.Close()
		t.Fatal("could not create the outer-parent nonce")
	}
	nonce := hex.EncodeToString(nonceBytes)
	sentinelPIDFD := -1
	startSentinel := exec.Command(executable, "-test.run=^TestCheckpointLocalObserverKernelSentinel$", "-test.timeout=170s")
	startSentinel.SysProcAttr = &syscall.SysProcAttr{PidFD: &sentinelPIDFD}
	startSentinel.Env = []string{checkpointLocalObserverParentMode + "=sentinel", "PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	startSentinel.Stdout, startSentinel.Stderr = io.Discard, io.Discard
	if err := startSentinel.Start(); err != nil {
		_ = reportFD.Close()
		t.Fatalf("could not start directly owned bounded outside sentinel: %v", err)
	}
	sentinelPID := startSentinel.Process.Pid
	if sentinelPIDFD < 0 {
		_ = reportFD.Close()
		t.Fatal("could not hold directly owned outside sentinel pidfd; preserving bounded sentinel")
	}
	wrapperCgroup, err := checkpointLocalObserverProcessCgroup(os.Getpid())
	if err != nil {
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("could not pin the test wrapper cgroup; preserving bounded sentinel")
	}
	sentinelCgroup, err := checkpointLocalObserverProcessCgroup(sentinelPID)
	if err != nil || sentinelCgroup != wrapperCgroup {
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("outside sentinel is not in the directly owning wrapper cgroup")
	}
	sentinelStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(sentinelPID)), sentinelPID)
	if err != nil || sentinelStart == 0 || checkpointLocalObserverPidfdTarget(sentinelPIDFD) != sentinelPID || checkpointLocalPIDFDAlive(sentinelPIDFD) != nil {
		_ = unix.PidfdSendSignal(sentinelPIDFD, unix.SIGKILL, nil, 0)
		_ = checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 2*time.Second)
		_ = unix.Close(sentinelPIDFD)
		_ = reportFD.Close()
		_ = startSentinel.Wait()
		t.Fatal("outside sentinel identity was not pinned before fixture launch")
	}
	sentinelDuplicate, err := unix.Dup(sentinelPIDFD)
	if err != nil {
		_ = unix.PidfdSendSignal(sentinelPIDFD, unix.SIGKILL, nil, 0)
		_ = checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 2*time.Second)
		_ = unix.Close(sentinelPIDFD)
		_ = reportFD.Close()
		_ = startSentinel.Wait()
		t.Fatal("could not duplicate the held outside sentinel descriptor for the fixture parent")
	}
	sentinelPassFD := os.NewFile(uintptr(sentinelDuplicate), "outer-parent-sentinel-pidfd")
	parentSocketPair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = sentinelPassFD.Close()
		_ = unix.PidfdSendSignal(sentinelPIDFD, unix.SIGKILL, nil, 0)
		_ = checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 2*time.Second)
		_ = unix.Close(sentinelPIDFD)
		_ = reportFD.Close()
		_ = startSentinel.Wait()
		t.Fatal("could not create the bounded coordinator-custody socketpair")
	}
	parentControlSocket := os.NewFile(uintptr(parentSocketPair[0]), "outer-parent-control-socket")
	childControlSocket := os.NewFile(uintptr(parentSocketPair[1]), "fixture-parent-control-socket")
	parentPIDFD := -1
	parent := exec.Command(executable, "-test.run=^TestCheckpointLocalObserverKernelFixture$", "-test.count=1", "-test.timeout=150s")
	parent.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}
	parent.Env = []string{checkpointLocalObserverKernelOptIn + "=1", checkpointLocalObserverParentMode + "=unit-owning-parent", checkpointLocalObserverParentNonce + "=" + nonce, "CHECKPOINT_LOCAL_OBSERVER_WRAPPER_CGROUP=" + wrapperCgroup, "PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	parent.ExtraFiles = []*os.File{reportFD, sentinelPassFD, childControlSocket}
	parentOutput := &checkpointLocalObserverParentOutputCapture{}
	parent.Stdout, parent.Stderr = parentOutput, parentOutput
	if err := parent.Start(); err != nil {
		_ = sentinelPassFD.Close()
		_ = parentControlSocket.Close()
		_ = childControlSocket.Close()
		_ = reportFD.Close()
		_ = unix.PidfdSendSignal(sentinelPIDFD, unix.SIGKILL, nil, 0)
		_ = checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 2*time.Second)
		_ = unix.Close(sentinelPIDFD)
		_ = startSentinel.Wait()
		t.Fatalf("could not start separately bounded unit-owning fixture parent: %v", err)
	}
	_ = childControlSocket.Close()
	parentPID := parent.Process.Pid
	if parentPIDFD < 0 {
		_ = sentinelPassFD.Close()
		_ = reportFD.Close()
		t.Fatalf("could not hold the separately launched fixture-parent pidfd; preserving private state: %v", err)
	}
	parentStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(parentPID)), parentPID)
	if err != nil || parentStart == 0 || checkpointLocalObserverPidfdTarget(parentPIDFD) != parentPID || checkpointLocalPIDFDAlive(parentPIDFD) != nil {
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		t.Fatal("separately launched fixture-parent identity was not pinned while live; preserving private state")
	}
	_ = sentinelPassFD.Close()
	coordinatorPIDFD, coordinatorPID, coordinatorStart, custodyErr := checkpointLocalObserverReceiveCoordinatorCustody(parentControlSocket, nonce, 140*time.Second)
	if custodyErr != nil || coordinatorPID <= 1 || coordinatorStart == 0 {
		reason := checkpointLocalObserverCustodyFailureClass(custodyErr)
		parentClass := checkpointLocalObserverParentFailureClass(parentOutput)
		parentStatus := checkpointLocalObserverParentTerminalClass(parentPIDFD)
		t.Logf("__CHECKPOINT_LOCAL_OBSERVER_PARENT_FAILURE__ reason=%s parent=%s status=%s", reason, parentClass, parentStatus)
		_ = parentControlSocket.Close()
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		_ = unix.Close(parentPIDFD)
		t.Fatalf("coordinator pidfd custody was not transferred; preserving report and bounded fixture children (%s)", reason)
	}
	parentErr := parent.Wait()
	var exitErr *exec.ExitError
	if !errors.As(parentErr, &exitErr) || exitErr.ExitCode() != checkpointLocalObserverParentExit {
		_ = parentControlSocket.Close()
		_ = unix.Close(coordinatorPIDFD)
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatalf("fixture parent did not take its distinct armed abrupt-exit path; report and children are preserved: %v", parentErr)
	}
	if checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD, 78*time.Second) != nil {
		_ = parentControlSocket.Close()
		_ = unix.Close(coordinatorPIDFD)
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("detached coordinator original pidfd did not confirm bounded terminal completion; preserving artifacts")
	}
	if checkpointLocalObserverPidfdTarget(coordinatorPIDFD) != -1 {
		_ = parentControlSocket.Close()
		_ = unix.Close(coordinatorPIDFD)
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("coordinator pidfd did not reach its exact terminal state; preserving artifacts")
	}
	_ = unix.Close(coordinatorPIDFD)
	if err := checkpointLocalObserverReadCoordinatorCompletion(parentControlSocket, nonce, 3*time.Second); err != nil {
		_ = parentControlSocket.Close()
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatalf("coordinator did not prove durable report completion before terminal exit; preserving artifacts: %v", err)
	}
	_ = parentControlSocket.Close()
	if checkpointLocalObserverWaitPidfdExited(parentPIDFD, 10*time.Millisecond) != nil {
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("outer fixture-parent pidfd did not confirm the exact expected process exit")
	}
	reportName := "parent-death.json"
	deadline := time.Now().Add(78 * time.Second)
	var report checkpointLocalObserverParentDeathReport
	for time.Now().Before(deadline) {
		candidate, readErr := checkpointLocalObserverReadParentDeathReport(reportFD, reportName, reportInfo)
		if readErr == nil && checkpointLocalObserverParentDeathReportValid(candidate, nonce, parentPID, parentStart, sentinelPID, sentinelStart, sentinelCgroup, checkpointLocalObserverParentExit) {
			report = candidate
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if report.Nonce == "" {
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatalf("independent parent-death coordinator report was not confirmed; preserving report directory %s and bounded sentinel", reportDir)
	}
	reportJSON, marshalErr := json.Marshal(report)
	if marshalErr != nil || len(reportJSON) > 4096 {
		_ = unix.Close(parentPIDFD)
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatal("verified parent-death report could not be canonically summarized")
	}
	fmt.Printf("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_REPORT__:%s\n", base64.RawStdEncoding.EncodeToString(reportJSON))
	fmt.Printf("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_NONCE__:%s\n", nonce)
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_COMPLETION__")
	_ = unix.Close(parentPIDFD)
	if err := checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 3*time.Second); err != nil {
		_ = unix.Close(sentinelPIDFD)
		t.Fatalf("coordinator did not exactly reap the outside sentinel; preserving report directory %s: %v", reportDir, err)
	}
	if err := startSentinel.Wait(); err != nil {
		_ = reportFD.Close()
		_ = unix.Close(sentinelPIDFD)
		t.Fatalf("outside sentinel child could not be reaped by its direct owner: %v", err)
	}
	_ = unix.Close(sentinelPIDFD)
	_ = reportFD.Close()
	currentInfo, err := os.Lstat(reportDir)
	if err != nil || !os.SameFile(reportInfo, currentInfo) || currentInfo.Mode().Perm() != 0700 {
		t.Fatalf("report directory identity changed after independent cleanup; preserving %s", reportDir)
	}
	entries, err := os.ReadDir(reportDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != reportName {
		t.Fatalf("private parent-death report inventory is not exact; preserving %s", reportDir)
	}
	if err := os.RemoveAll(reportDir); err != nil {
		t.Fatalf("could not remove exact completed report directory %s: %v", reportDir, err)
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KERNEL_OUTER_PARENT_DEATH__")
}

func checkpointLocalObserverParentDeathReportValid(report checkpointLocalObserverParentDeathReport, nonce string, parentPID int, parentStart uint64, sentinelPID int, sentinelStart uint64, sentinelCgroup string, expectedExit int) bool {
	decodedNonce, nonceErr := hex.DecodeString(report.Nonce)
	if nonceErr != nil || len(decodedNonce) != 16 || report.Version != 1 || report.Nonce != nonce || report.ParentPID != parentPID || report.ParentStart != parentStart || report.ExpectedParentExit != expectedExit || !report.ParentDeathObserved || report.PostDeathLiveUnits != 3 || report.MaxLiveUnitAgeMs < 0 || report.MaxLiveUnitAgeMs > 150000 || !report.OriginalWorkerExited || !report.SentinelSurvived || !report.SentinelExited || !report.RootRemoved || report.SentinelPID != sentinelPID || report.SentinelStart != sentinelStart || report.SentinelCgroup != sentinelCgroup {
		return false
	}
	seen := map[string]bool{}
	for i, role := range []string{"original-worker", "replacement-worker", "unrelated-control", "broker"} {
		if !report.UnitsAbsent[i] || report.UnitRoles[i] != role || report.UnitNames[i] == "" || seen[report.UnitNames[i]] {
			return false
		}
		seen[report.UnitNames[i]] = true
	}
	return sentinelPID > 1 && sentinelStart > 0 && sentinelCgroup != ""
}

func checkpointLocalObserverReadParentDeathReport(dir *os.File, name string, dirInfo os.FileInfo) (checkpointLocalObserverParentDeathReport, error) {
	var report checkpointLocalObserverParentDeathReport
	if dir == nil || name != "parent-death.json" || dirInfo == nil {
		return report, errors.New("invalid held parent-death report directory")
	}
	beforeDir, err := dir.Stat()
	if err != nil || !beforeDir.IsDir() || !os.SameFile(dirInfo, beforeDir) || beforeDir.Mode().Perm() != 0700 {
		return report, errors.New("held report-directory identity changed")
	}
	dirStat, ok := beforeDir.Sys().(*syscall.Stat_t)
	dirPath, pathReadErr := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(int(dir.Fd()))))
	currentDirPath, pathErr := os.Lstat(dirPath)
	if !ok || dirStat.Uid != 0 || pathReadErr != nil || pathErr != nil || !os.SameFile(beforeDir, currentDirPath) || currentDirPath.Mode()&os.ModeSymlink != 0 {
		return report, errors.New("held report directory no longer matches its pinned root-owned path")
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return report, err
	}
	file := os.NewFile(uintptr(fd), "held-parent-death-report")
	defer file.Close()
	before, err := file.Stat()
	var beforeStat *syscall.Stat_t
	if before != nil {
		beforeStat, _ = before.Sys().(*syscall.Stat_t)
	}
	beforeOK := beforeStat != nil
	if err != nil || !beforeOK || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() <= 0 || before.Size() > 4096 || beforeStat.Uid != 0 || beforeStat.Nlink != 1 {
		return report, errors.New("parent-death report is not one bounded root-private regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return report, errors.New("parent-death report is partial or exceeds its bound")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
		return report, errors.New("parent-death report changed while read")
	}
	var pathStat unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), name, &pathStat, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil || uint64(pathStat.Dev) != uint64(beforeStat.Dev) || pathStat.Ino != beforeStat.Ino || pathStat.Nlink != 1 || pathStat.Uid != 0 || pathStat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return report, errors.New("parent-death report path no longer names the exact private held inode")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return report, err
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || checkpointLocalObserverRejectDuplicateKeys(data) != nil {
		return report, errors.New("parent-death report has trailing or duplicate JSON content")
	}
	canonical, err := json.Marshal(report)
	if err != nil || !bytes.Equal(canonical, data) {
		return report, errors.New("parent-death report is not canonical JSON")
	}
	afterDir, dirErr := dir.Stat()
	currentDirPath, pathErr = os.Lstat(dirPath)
	if dirErr != nil || !os.SameFile(beforeDir, afterDir) || pathErr != nil || !os.SameFile(beforeDir, currentDirPath) || currentDirPath.Mode().Perm() != 0700 {
		return report, errors.New("held report directory changed during the report read")
	}
	return report, nil
}

func checkpointLocalObserverResolveHeldParentReportPath(dir *os.File, heldInfo os.FileInfo, readlink func(string) (string, error)) (string, error) {
	if dir == nil || heldInfo == nil || readlink == nil {
		return "", errors.New("invalid held parent report directory")
	}
	before, err := dir.Stat()
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0700 || !os.SameFile(heldInfo, before) {
		return "", errors.New("held parent report directory identity changed")
	}
	heldStat, heldOK := heldInfo.Sys().(*syscall.Stat_t)
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	if !heldOK || !beforeOK || heldStat.Uid != 0 || beforeStat.Uid != 0 || heldStat.Dev != beforeStat.Dev || heldStat.Ino != beforeStat.Ino {
		return "", errors.New("held parent report directory owner or inode pin changed")
	}
	fdPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(dir.Fd())))
	resolved, err := readlink(fdPath)
	if err != nil || !filepath.IsAbs(resolved) {
		return "", errors.New("held parent report descriptor has no absolute path")
	}
	named, err := os.Lstat(resolved)
	if err != nil {
		return "", errors.New("held parent report path is unavailable")
	}
	if !os.SameFile(before, named) {
		return "", errors.New("held report path identity mismatch")
	}
	namedStat, namedOK := named.Sys().(*syscall.Stat_t)
	if !named.IsDir() || named.Mode()&os.ModeSymlink != 0 || named.Mode().Perm() != 0700 || !namedOK || namedStat.Uid != 0 || namedStat.Dev != beforeStat.Dev || namedStat.Ino != beforeStat.Ino {
		return "", errors.New("held parent report path owner, mode, or inode pin changed")
	}
	after, err := dir.Stat()
	if err != nil || !after.IsDir() || after.Mode().Perm() != 0700 || !os.SameFile(before, after) {
		return "", errors.New("held parent report descriptor changed during path resolution")
	}
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	current, pathErr := os.Lstat(resolved)
	if pathErr != nil {
		return "", errors.New("held parent report path changed during resolution")
	}
	currentStat, currentOK := current.Sys().(*syscall.Stat_t)
	if !afterOK || !currentOK || afterStat.Uid != 0 || currentStat.Uid != 0 || afterStat.Dev != beforeStat.Dev || afterStat.Ino != beforeStat.Ino || currentStat.Dev != beforeStat.Dev || currentStat.Ino != beforeStat.Ino || !os.SameFile(before, current) || current.Mode()&os.ModeSymlink != 0 || current.Mode().Perm() != 0700 {
		return "", errors.New("held parent report path changed during resolution")
	}
	return resolved, nil
}

func checkpointLocalObserverKernelArmParentDeathCoordinator(t *testing.T, root string, rootStat *syscall.Stat_t, worker, replacement, unrelated, broker *checkpointLocalObserverFixtureUnit) {
	t.Helper()
	if worker == nil || replacement == nil || unrelated == nil || broker == nil || rootStat == nil || worker.pidfd < 0 || replacement.pidfd < 0 || unrelated.pidfd < 0 || broker.pidfd < 0 {
		t.Fatal("parent-death coordinator lacks original held unit descriptors; preserving the fixture")
	}
	reportDir := os.NewFile(checkpointLocalObserverParentReportFD, "outer-parent-report-dir")
	sentinelFile := os.NewFile(checkpointLocalObserverParentSentinelFD, "outer-parent-sentinel-pidfd")
	if reportDir == nil || sentinelFile == nil {
		t.Fatal("parent-death coordinator inheritance descriptors are missing; preserving the fixture")
	}
	reportInfo, err := reportDir.Stat()
	if err != nil || !reportInfo.IsDir() || reportInfo.Mode().Perm() != 0700 {
		t.Fatal("inherited outer-parent report directory identity is invalid; preserving the fixture")
	}
	reportStat, ok := reportInfo.Sys().(*syscall.Stat_t)
	if !ok || reportStat.Uid != 0 {
		t.Fatal("inherited report directory is not root-owned; preserving the fixture")
	}
	sentinelPID := checkpointLocalObserverPidfdTarget(int(sentinelFile.Fd()))
	sentinelStart, sentinelErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(sentinelPID)), sentinelPID)
	sentinelCgroup, cgroupErr := checkpointLocalObserverProcessCgroup(sentinelPID)
	parentCgroup, parentCgroupErr := checkpointLocalObserverProcessCgroup(os.Getpid())
	if sentinelPID <= 1 || sentinelErr != nil || sentinelStart == 0 || cgroupErr != nil || parentCgroupErr != nil || sentinelCgroup != parentCgroup || sentinelCgroup != os.Getenv("CHECKPOINT_LOCAL_OBSERVER_WRAPPER_CGROUP") || checkpointLocalPIDFDAlive(int(sentinelFile.Fd())) != nil {
		t.Fatal("inherited outside sentinel pidfd is not current; preserving the fixture")
	}
	rootFD, err := os.Open(root)
	if err != nil {
		t.Fatal("could not hold private fixture root for the coordinator; preserving it")
	}
	defer rootFD.Close()
	rootInfo, err := rootFD.Stat()
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode().Perm() != 0711 {
		t.Fatal("held fixture root mode or type changed before coordinator arm; preserving it")
	}
	currentRoot, err := os.Lstat(root)
	if err != nil || !os.SameFile(rootInfo, currentRoot) || currentRoot.Mode()&os.ModeSymlink != 0 {
		t.Fatal("fixture root path no longer matches its held directory descriptor; preserving it")
	}
	rootHeldStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootHeldStat.Dev != rootStat.Dev || rootHeldStat.Ino != rootStat.Ino || rootHeldStat.Uid != 0 {
		t.Fatal("fixture root dev/inode/owner pin changed; preserving it")
	}
	if int(reportDir.Fd()) != checkpointLocalObserverParentReportFD || checkpointLocalObserverParentReportFD != 3 || checkpointLocalObserverReportFD != 10 || checkpointLocalObserverParentReportFD == checkpointLocalObserverReportFD || os.SameFile(reportInfo, rootInfo) {
		t.Fatal("unit-owning parent report descriptor roles are not distinct and exact; preserving all objects")
	}
	positiveReportPath, positivePathErr := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, func(fdPath string) (string, error) {
		if fdPath != filepath.Join("/proc/self/fd", strconv.Itoa(checkpointLocalObserverParentReportFD)) {
			return "", errors.New("parent report lookup did not request inherited fd three")
		}
		return os.Readlink(fdPath)
	})
	if positivePathErr != nil || positiveReportPath == "" {
		t.Fatal("held report path positive did not resolve the exact inherited fd three; preserving all objects")
	}
	_, decoyPathErr := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, func(fdPath string) (string, error) {
		if fdPath != filepath.Join("/proc/self/fd", strconv.Itoa(checkpointLocalObserverParentReportFD)) {
			return "", errors.New("decoy report lookup did not request inherited fd three")
		}
		return root, nil
	})
	if decoyPathErr == nil || decoyPathErr.Error() != "held report path identity mismatch" {
		t.Fatal("held report path helper did not specifically reject the distinct existing fixture-root decoy; preserving all objects")
	}
	parentPID := os.Getpid()
	parentSocket := os.NewFile(checkpointLocalObserverParentSocketFD, "fixture-parent-coordinator-custody")
	if parentSocket == nil {
		t.Fatal("fixture parent lacks its held coordinator-custody socket; preserving all objects")
	}
	parentPIDFD, err := unix.PidfdOpen(parentPID, 0)
	if err != nil {
		t.Fatal("could not hold original fixture parent pidfd; preserving units and root")
	}
	defer unix.Close(parentPIDFD)
	parentStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(parentPID)), parentPID)
	if err != nil || parentStart == 0 || checkpointLocalObserverPidfdTarget(parentPIDFD) != parentPID || checkpointLocalPIDFDAlive(parentPIDFD) != nil {
		t.Fatal("original fixture parent pidfd/start identity is not current; preserving units and root")
	}
	units := [4]*checkpointLocalObserverFixtureUnit{worker, replacement, unrelated, broker}
	roles := [4]string{"original-worker", "replacement-worker", "unrelated-control", "broker"}
	unitPins := [4]checkpointLocalObserverParentUnit{}
	for i, fixture := range units {
		if fixture.pid <= 1 || fixture.start == 0 || fixture.startedAt <= 0 || !checkpointLocalObserverValidInvocation(fixture.invocation) || fixture.cgroup == "" || !strings.HasPrefix(fixture.name, "checkpoint-local-observer-fixture-") {
			t.Fatalf("fixture unit %s lacks its exact original identity tuple; preserving all objects", roles[i])
		}
		unitPins[i] = checkpointLocalObserverParentUnit{Role: roles[i], Name: fixture.name, PID: fixture.pid, Start: fixture.start, StartedMonoNS: fixture.startedAt, Invocation: fixture.invocation, Cgroup: fixture.cgroup}
		if fixture.cgroup == sentinelCgroup {
			t.Fatal("outside sentinel shares a fixture unit cgroup; preserving all objects")
		}
		if i == 0 {
			if checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 10*time.Millisecond) != nil {
				t.Fatal("original worker pidfd is not already terminal before replacement handoff; preserving all objects")
			}
			state, stateErr := checkpointLocalObserverShowFixtureUnit(fixture.name)
			if stateErr != nil || state["LoadState"] != "not-found" {
				t.Fatal("original worker unit absence was not confirmed before replacement; preserving all objects")
			}
			continue
		}
		if err := checkpointLocalObserverVerifyParentDeathUnit(fixture, true); err != nil {
			t.Fatalf("parent-death unit tuple is not independently current: %v; preserving all objects", err)
		}
	}
	nonce := os.Getenv(checkpointLocalObserverParentNonce)
	decodedNonce, nonceErr := hex.DecodeString(nonce)
	if nonceErr != nil || len(decodedNonce) != 16 || nonce != strings.ToLower(nonce) {
		t.Fatal("outer fixture parent lacks its exact externally held nonce; preserving all objects")
	}
	reportDirPath, err := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, os.Readlink)
	if err != nil {
		t.Fatal("inherited report-directory path does not match its held descriptor; preserving all objects")
	}
	config := checkpointLocalObserverParentDeathConfig{
		Version: 1, Nonce: nonce, Root: root, RootDev: uint64(rootHeldStat.Dev), RootIno: rootHeldStat.Ino,
		ReportDir: reportDirPath, ReportDev: uint64(reportStat.Dev), ReportIno: reportStat.Ino,
		ReportName: "parent-death.json", ParentPID: parentPID, ParentStart: parentStart,
		SentinelPID: sentinelPID, SentinelStart: sentinelStart, SentinelCgroup: os.Getenv("CHECKPOINT_LOCAL_OBSERVER_WRAPPER_CGROUP"), Units: unitPins,
	}
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) > 8192 {
		t.Fatal("bounded parent-death coordinator configuration could not be encoded; preserving all objects")
	}
	ackRead, ackWrite, err := os.Pipe()
	if err != nil {
		t.Fatal("could not create coordinator readiness channel; preserving all objects")
	}
	defer ackRead.Close()
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		_ = ackWrite.Close()
		t.Fatal("could not resolve exact coordinator executable; preserving all objects")
	}
	coordinatorPIDFD := -1
	coordinator := exec.Command(executable, "-test.run=^TestCheckpointLocalObserverKernelParentDeathCoordinator$", "-test.count=1", "-test.timeout=70s")
	coordinator.Env = []string{checkpointLocalObserverParentMode + "=coordinator", "PATH=/usr/bin:/bin", "HOME=/root", "LANG=C", "LC_ALL=C"}
	coordinator.Stdin = strings.NewReader(string(encoded))
	coordinator.Stdout, coordinator.Stderr = io.Discard, io.Discard
	passFiles := make([]*os.File, 0, 10)
	for _, item := range []struct {
		fd   int
		name string
	}{{parentPIDFD, "original-parent-pidfd"}, {worker.pidfd, "original-worker-pidfd"}, {replacement.pidfd, "replacement-worker-pidfd"}, {unrelated.pidfd, "unrelated-control-pidfd"}, {broker.pidfd, "broker-pidfd"}, {int(rootFD.Fd()), "held-fixture-root"}, {int(sentinelFile.Fd()), "outside-sentinel-pidfd"}, {int(reportDir.Fd()), "held-report-directory"}, {int(ackWrite.Fd()), "coordinator-ack"}, {int(parentSocket.Fd()), "wrapper-completion-socket"}} {
		dup, dupErr := unix.Dup(item.fd)
		if dupErr != nil {
			for _, passed := range passFiles {
				_ = passed.Close()
			}
			_ = ackWrite.Close()
			t.Fatalf("could not duplicate exact coordinator descriptor role %s; preserving all objects", item.name)
		}
		passFiles = append(passFiles, os.NewFile(uintptr(dup), item.name))
	}
	coordinator.ExtraFiles = passFiles
	coordinator.SysProcAttr = &syscall.SysProcAttr{Setsid: true, PidFD: &coordinatorPIDFD}
	if err := coordinator.Start(); err != nil {
		for _, passed := range passFiles {
			_ = passed.Close()
		}
		_ = ackWrite.Close()
		t.Fatal("detached parent-death coordinator did not start; preserving all objects")
	}
	for _, passed := range passFiles {
		_ = passed.Close()
	}
	if coordinatorPIDFD < 0 || checkpointLocalObserverPidfdTarget(coordinatorPIDFD) != coordinator.Process.Pid {
		_ = parentSocket.Close()
		t.Fatal("coordinator original pidfd was not atomically held; preserving all objects")
	}
	coordinatorStart, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(coordinator.Process.Pid)), coordinator.Process.Pid)
	if startErr != nil || coordinatorStart == 0 || checkpointLocalPIDFDAlive(coordinatorPIDFD) != nil {
		_ = unix.Close(coordinatorPIDFD)
		_ = parentSocket.Close()
		t.Fatal("coordinator PID/start custody did not match its original pidfd; preserving all objects")
	}
	custody := []byte(fmt.Sprintf("COORDINATOR:%s:%d:%d", nonce, coordinator.Process.Pid, coordinatorStart))
	if written, sendErr := unix.SendmsgN(int(parentSocket.Fd()), custody, unix.UnixRights(coordinatorPIDFD), nil, 0); sendErr != nil || written != len(custody) {
		_ = unix.Close(coordinatorPIDFD)
		_ = parentSocket.Close()
		t.Fatal("could not transfer exactly one coordinator pidfd to the surviving wrapper; preserving all objects")
	}
	_ = unix.Close(coordinatorPIDFD)
	_ = parentSocket.Close()
	_ = ackWrite.Close()
	if err := checkpointLocalObserverReadCoordinatorAck(ackRead, nonce, 8*time.Second); err != nil {
		t.Fatalf("coordinator did not ACK verified descriptor custody; preserving all units and root: %v", err)
	}
	if checkpointLocalPIDFDAlive(parentPIDFD) != nil || checkpointLocalObserverPidfdTarget(parentPIDFD) != parentPID {
		t.Fatal("fixture parent identity changed before the acknowledged abrupt exit; preserving all objects")
	}
}

func checkpointLocalObserverKernelRunParentDeathCoordinator(t *testing.T) {
	t.Helper()
	configBytes, err := io.ReadAll(io.LimitReader(os.Stdin, 8193))
	if err != nil || len(configBytes) == 0 || len(configBytes) > 8192 {
		t.Fatal("coordinator configuration is absent or exceeds its bound")
	}
	var config checkpointLocalObserverParentDeathConfig
	decoder := json.NewDecoder(strings.NewReader(string(configBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		t.Fatal("coordinator configuration did not decode strictly")
	}
	var trailing any
	decodedConfigNonce, configNonceErr := hex.DecodeString(config.Nonce)
	if decoder.Decode(&trailing) != io.EOF || checkpointLocalObserverRejectDuplicateKeys(configBytes) != nil || configNonceErr != nil || len(decodedConfigNonce) != 16 || config.Version != 1 || config.Nonce != strings.ToLower(config.Nonce) || config.ParentPID <= 1 || config.ParentStart == 0 || config.SentinelPID <= 1 || config.SentinelStart == 0 || config.ReportName != "parent-death.json" {
		t.Fatal("coordinator configuration identity, nonce, or trailing bytes are invalid")
	}
	canonicalConfig, marshalErr := json.Marshal(config)
	if marshalErr != nil || !bytes.Equal(canonicalConfig, configBytes) {
		t.Fatal("coordinator config is not canonical JSON")
	}
	fds := []int{checkpointLocalObserverParentFD, checkpointLocalObserverWorkerFD, checkpointLocalObserverReplaceFD, checkpointLocalObserverUnrelatedFD, checkpointLocalObserverBrokerFD, checkpointLocalObserverRootFD, checkpointLocalObserverSentinelFD, checkpointLocalObserverReportFD, checkpointLocalObserverAckFD, checkpointLocalObserverCompletionFD}
	files := make([]*os.File, len(fds))
	for i, fd := range fds {
		files[i] = os.NewFile(uintptr(fd), "parent-death-held-descriptor")
		if files[i] == nil {
			t.Fatal("coordinator descriptor role mapping is incomplete")
		}
		defer files[i].Close()
	}
	parentPIDFD, workerPIDFD, replacementPIDFD, unrelatedPIDFD, brokerPIDFD := fds[0], fds[1], fds[2], fds[3], fds[4]
	rootFD, sentinelPIDFD, reportFD, ackFD := fds[5], fds[6], fds[7], fds[8]
	completionFD := fds[9]
	parentStart, parentErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(config.ParentPID)), config.ParentPID)
	if parentErr != nil || parentStart != config.ParentStart || checkpointLocalObserverPidfdTarget(parentPIDFD) != config.ParentPID || checkpointLocalPIDFDAlive(parentPIDFD) != nil {
		t.Fatal("coordinator could not independently verify the original live fixture-parent pidfd/start")
	}
	rootHeld, err := files[5].Stat()
	if err != nil || !rootHeld.IsDir() || rootHeld.Mode().Perm() != 0711 {
		t.Fatal("coordinator fixture-root descriptor is not the exact held searchable directory")
	}
	rootStat, ok := rootHeld.Sys().(*syscall.Stat_t)
	rootPath, rootPathErr := os.Lstat(config.Root)
	if !ok || rootStat.Uid != 0 || rootStat.Dev != config.RootDev || rootStat.Ino != config.RootIno || rootPathErr != nil || !os.SameFile(rootHeld, rootPath) || rootPath.Mode()&os.ModeSymlink != 0 {
		t.Fatal("coordinator root descriptor/path dev-inode-owner pin did not match")
	}
	reportHeld, err := files[7].Stat()
	if err != nil || !reportHeld.IsDir() || reportHeld.Mode().Perm() != 0700 {
		t.Fatal("coordinator report-directory descriptor is not root-private")
	}
	reportStat, ok := reportHeld.Sys().(*syscall.Stat_t)
	if !ok || reportStat.Uid != 0 || reportStat.Dev != config.ReportDev || reportStat.Ino != config.ReportIno || rootFD != int(files[5].Fd()) {
		t.Fatal("coordinator report directory identity differs from its held original descriptor")
	}
	if checkpointLocalObserverPidfdTarget(sentinelPIDFD) != config.SentinelPID || checkpointLocalPIDFDAlive(sentinelPIDFD) != nil {
		t.Fatal("coordinator outside-sentinel pidfd is not the exact live original process")
	}
	sentinelCgroup, cgroupErr := checkpointLocalObserverProcessCgroup(config.SentinelPID)
	parentCgroup, parentCgroupErr := checkpointLocalObserverProcessCgroup(config.ParentPID)
	if cgroupErr != nil || parentCgroupErr != nil || sentinelCgroup == "" || sentinelCgroup != config.SentinelCgroup || sentinelCgroup != parentCgroup {
		t.Fatal("coordinator did not independently join outside sentinel and original parent cgroups")
	}
	for i, unit := range config.Units {
		if unit.Role != [4]string{"original-worker", "replacement-worker", "unrelated-control", "broker"}[i] || unit.PID <= 1 || unit.Start == 0 || unit.StartedMonoNS <= 0 || !checkpointLocalObserverValidInvocation(unit.Invocation) || unit.Cgroup == "" || unit.Cgroup == sentinelCgroup {
			t.Fatal("coordinator unit tuple order or identity fields are invalid")
		}
		pidfd := []int{workerPIDFD, replacementPIDFD, unrelatedPIDFD, brokerPIDFD}[i]
		fixture := &checkpointLocalObserverFixtureUnit{name: unit.Name, pid: unit.PID, start: unit.Start, invocation: unit.Invocation, cgroup: unit.Cgroup, owned: true, pidfd: pidfd}
		if i == 0 {
			if err := checkpointLocalObserverWaitPidfdExited(pidfd, 10*time.Millisecond); err != nil {
				t.Fatal("original worker pidfd was not terminal before replacement publication")
			}
			state, stateErr := checkpointLocalObserverShowFixtureUnit(unit.Name)
			if stateErr != nil || state["LoadState"] != "not-found" {
				t.Fatal("original worker exact unit was not stably absent before replacement")
			}
			continue
		}
		if err := checkpointLocalObserverVerifyParentDeathUnit(fixture, true); err != nil {
			t.Fatalf("coordinator could not independently join unit pidfd/start/invocation/cgroup: %v", err)
		}
	}
	if config.Units[0].Name == config.Units[1].Name || config.Units[0].Name == config.Units[2].Name || config.Units[0].Name == config.Units[3].Name || config.Units[1].Name == config.Units[2].Name || config.Units[1].Name == config.Units[3].Name || config.Units[2].Name == config.Units[3].Name {
		t.Fatal("coordinator received duplicate fixture unit names")
	}
	if err := checkpointLocalObserverVerifyParentDeathUnit(&checkpointLocalObserverFixtureUnit{name: config.Units[0].Name, pid: config.Units[0].PID, start: config.Units[0].Start, invocation: config.Units[0].Invocation, cgroup: config.Units[0].Cgroup, owned: true, pidfd: workerPIDFD}, false); err != nil {
		t.Fatal("original worker unit terminal state is not independently pinned")
	}
	ack := []byte("ARMED:" + config.Nonce + "\n")
	if written, err := unix.Write(ackFD, ack); err != nil || written != len(ack) {
		t.Fatal("coordinator could not publish its nonce-bound descriptor-custody ACK")
	}
	if err := checkpointLocalObserverWaitPidfdExited(parentPIDFD, 15*time.Second); err != nil {
		t.Fatal("coordinator did not observe abrupt original fixture-parent death before its bound")
	}
	var report checkpointLocalObserverParentDeathReport
	report.Version, report.Nonce, report.ParentPID, report.ParentStart = 1, config.Nonce, config.ParentPID, config.ParentStart
	report.ExpectedParentExit, report.ParentDeathObserved, report.OriginalWorkerExited = checkpointLocalObserverParentExit, true, true
	report.SentinelPID, report.SentinelStart, report.SentinelCgroup = config.SentinelPID, config.SentinelStart, config.SentinelCgroup
	report.SentinelSurvived = checkpointLocalObserverPidfdTarget(sentinelPIDFD) == config.SentinelPID && checkpointLocalPIDFDAlive(sentinelPIDFD) == nil
	if !report.SentinelSurvived {
		t.Fatal("outside sentinel did not remain alive after original fixture-parent death")
	}
	for i, unit := range config.Units {
		report.UnitRoles[i], report.UnitNames[i] = unit.Role, unit.Name
		if i == 0 {
			continue
		}
		nowMonoNS, monoErr := checkpointLocalObserverMonotonicNS()
		ageNS := nowMonoNS - unit.StartedMonoNS
		if monoErr != nil || ageNS <= 0 || ageNS > int64(150*time.Second) {
			t.Fatal("post-parent-death control entered cleanup without a meaningful margin before RuntimeMaxSec")
		}
		if ageMS := ageNS / int64(time.Millisecond); ageMS > report.MaxLiveUnitAgeMs {
			report.MaxLiveUnitAgeMs = ageMS
		}
		fixture := &checkpointLocalObserverFixtureUnit{name: unit.Name, pid: unit.PID, start: unit.Start, invocation: unit.Invocation, cgroup: unit.Cgroup, owned: true, pidfd: []int{workerPIDFD, replacementPIDFD, unrelatedPIDFD, brokerPIDFD}[i]}
		if err := checkpointLocalObserverVerifyParentDeathUnit(fixture, true); err != nil {
			t.Fatal("one of the exact broker/replacement/unrelated units was not LIVE after parent death")
		}
		report.PostDeathLiveUnits++
	}
	if report.PostDeathLiveUnits != 3 || checkpointLocalObserverWaitPidfdExited(workerPIDFD, 10*time.Millisecond) != nil {
		t.Fatal("post-parent-death live-unit count or original worker exit state is invalid")
	}
	for _, i := range []int{3, 1, 2} {
		unit := config.Units[i]
		fixture := &checkpointLocalObserverFixtureUnit{name: unit.Name, pid: unit.PID, start: unit.Start, invocation: unit.Invocation, cgroup: unit.Cgroup, owned: true, pidfd: []int{workerPIDFD, replacementPIDFD, unrelatedPIDFD, brokerPIDFD}[i]}
		if err := checkpointLocalObserverStopParentDeathUnit(fixture); err != nil {
			t.Fatalf("coordinator exact pidfd cleanup failed for %s; preserving uncertain objects: %v", unit.Role, err)
		}
		if err := checkpointLocalObserverVerifyParentDeathUnit(fixture, false); err != nil {
			t.Fatalf("coordinator exact unit absence was not stable for %s: %v", unit.Role, err)
		}
		report.UnitsAbsent[i] = true
	}
	if !report.UnitsAbsent[0] {
		if err := checkpointLocalObserverVerifyParentDeathUnit(&checkpointLocalObserverFixtureUnit{name: config.Units[0].Name, pid: config.Units[0].PID, start: config.Units[0].Start, invocation: config.Units[0].Invocation, cgroup: config.Units[0].Cgroup, owned: true, pidfd: workerPIDFD}, false); err != nil {
			t.Fatal("original worker absence changed during exact remaining-unit cleanup")
		}
		report.UnitsAbsent[0] = true
	}
	if checkpointLocalObserverPidfdTarget(sentinelPIDFD) != config.SentinelPID || checkpointLocalPIDFDAlive(sentinelPIDFD) != nil {
		t.Fatal("outside sentinel failed to survive all exact unit cleanup")
	}
	sentinelStart, sentinelErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(config.SentinelPID)), config.SentinelPID)
	finalSentinelCgroup, finalCgroupErr := checkpointLocalObserverProcessCgroup(config.SentinelPID)
	if sentinelErr != nil || sentinelStart != config.SentinelStart || finalCgroupErr != nil || finalSentinelCgroup != config.SentinelCgroup {
		t.Fatal("outside sentinel start/cgroup identity changed during exact unit cleanup")
	}
	if _, err := os.Lstat(filepath.Join(config.Root, "run", "observer.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("exact observer socket absence was not confirmed after broker death")
	}
	rootNow, err := os.Lstat(config.Root)
	rootFDNow, rootFDErr := files[5].Stat()
	if err != nil || !os.SameFile(rootHeld, rootNow) || rootNow.Mode()&os.ModeSymlink != 0 || rootFDErr != nil || !os.SameFile(rootHeld, rootFDNow) || rootFDNow.Mode().Perm() != 0711 {
		t.Fatal("fixture root path changed before exact coordinator cleanup; preserving it")
	}
	if err := os.RemoveAll(config.Root); err != nil {
		t.Fatal("exact private fixture root removal failed; preserving external report uncertainty")
	}
	if _, err := os.Lstat(config.Root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("exact fixture root absence was not stable after coordinator cleanup")
	}
	rootFDNow, rootFDErr = files[5].Stat()
	if rootFDErr != nil || !os.SameFile(rootHeld, rootFDNow) || rootFDNow.Mode().Perm() != 0711 {
		t.Fatal("held fixture-root descriptor changed across exact root removal")
	}
	report.RootRemoved = true
	if err := unix.PidfdSendSignal(sentinelPIDFD, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal("coordinator could not terminate only the directly owned outside sentinel pidfd")
	}
	if err := checkpointLocalObserverWaitPidfdExited(sentinelPIDFD, 5*time.Second); err != nil {
		t.Fatal("coordinator could not confirm exact outside sentinel exit")
	}
	report.SentinelExited = true
	report.SentinelPID, report.SentinelStart = config.SentinelPID, config.SentinelStart
	if !checkpointLocalObserverParentDeathReportValid(report, config.Nonce, config.ParentPID, config.ParentStart, config.SentinelPID, config.SentinelStart, config.SentinelCgroup, checkpointLocalObserverParentExit) {
		t.Fatal("coordinator final report did not satisfy its complete nonce-bound proof schema")
	}
	encoded, err := json.Marshal(report)
	if err != nil || len(encoded) > 4096 {
		t.Fatal("coordinator report exceeds the strict bounded schema")
	}
	fd, err := unix.Openat(reportFD, config.ReportName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		t.Fatal("coordinator could not create its unique report through the held report-directory descriptor")
	}
	file := os.NewFile(uintptr(fd), "parent-death-report")
	writeErr := checkpointLocalObserverWriteFull(file, encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		t.Fatal("coordinator could not durably finish its bounded completion report")
	}
	if err := unix.Fsync(reportFD); err != nil {
		t.Fatal("coordinator could not durably publish its completion report directory entry")
	}
	completion := []byte("COMPLETE:" + config.Nonce)
	if written, err := unix.SendmsgN(completionFD, completion, nil, nil, 0); err != nil || written != len(completion) {
		t.Fatal("coordinator could not send its nonce-bound durable-completion packet")
	}
}

func checkpointLocalObserverReadCoordinatorAck(file *os.File, nonce string, timeout time.Duration) error {
	if file == nil || len(nonce) != 32 {
		return errors.New("invalid coordinator ACK reader or nonce")
	}
	deadline := time.Now().Add(timeout)
	buffer := make([]byte, 128)
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 25)
		if err != nil {
			if checkpointLocalObserverPollInterrupted(err) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL|unix.POLLHUP) != 0 {
			return errors.New("coordinator ACK pipe closed before complete readiness")
		}
		count, err := unix.Read(int(file.Fd()), buffer)
		if err != nil {
			return err
		}
		if count == 0 || count == len(buffer) {
			return errors.New("coordinator ACK is empty or exceeds its bound")
		}
		if string(buffer[:count]) != "ARMED:"+nonce+"\n" {
			return errors.New("coordinator ACK nonce or exact framing did not match")
		}
		return nil
	}
	return errors.New("coordinator ACK deadline expired")
}

func checkpointLocalObserverReceiveCoordinatorCustody(file *os.File, nonce string, timeout time.Duration) (int, int, uint64, error) {
	if file == nil || len(nonce) != 32 || timeout <= 0 {
		return -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverUnavailable)
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 25)
		if err != nil {
			if checkpointLocalObserverPollInterrupted(err) {
				continue
			}
			return -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverUnavailable)
		}
		if ready == 0 {
			continue
		}
		payload := make([]byte, 256)
		oob := make([]byte, unix.CmsgSpace(4*4))
		n, oobn, flags, _, err := unix.Recvmsg(int(file.Fd()), payload, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return -1, 0, 0, err
		}
		if flags&unix.MSG_TRUNC != 0 {
			return -1, 0, 0, errors.New(checkpointLocalObserverCustodyPayloadTruncated)
		}
		if flags&unix.MSG_CTRUNC != 0 {
			return -1, 0, 0, errors.New(checkpointLocalObserverCustodyAncillaryTruncated)
		}
		if n == 0 {
			return -1, 0, 0, errors.New(checkpointLocalObserverCustodyEmpty)
		}
		if n == len(payload) {
			return -1, 0, 0, errors.New(checkpointLocalObserverCustodyPayloadFull)
		}
		messages, err := unix.ParseSocketControlMessage(oob[:oobn])
		if err != nil || len(messages) != 1 {
			return -1, 0, 0, errors.New("coordinator custody packet has unexpected ancillary framing")
		}
		fds, err := unix.ParseUnixRights(&messages[0])
		if err != nil || len(fds) != 1 {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return -1, 0, 0, errors.New("coordinator custody packet did not contain exactly one pidfd")
		}
		pidfd := fds[0]
		text := string(payload[:n])
		parts := strings.Split(text, ":")
		if len(parts) != 4 || parts[0] != "COORDINATOR" || parts[1] != nonce {
			_ = unix.Close(pidfd)
			return -1, 0, 0, errors.New("coordinator custody nonce or packet schema mismatch")
		}
		pid, pidErr := strconv.Atoi(parts[2])
		start, startErr := strconv.ParseUint(parts[3], 10, 64)
		if pidErr != nil || startErr != nil || pid <= 1 || start == 0 || checkpointLocalObserverPidfdTarget(pidfd) != pid || checkpointLocalPIDFDAlive(pidfd) != nil {
			_ = unix.Close(pidfd)
			return -1, 0, 0, errors.New("coordinator transferred pidfd is not its exact live advertised process")
		}
		currentStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
		if err != nil || currentStart != start || checkpointLocalObserverPidfdTarget(pidfd) != pid || checkpointLocalPIDFDAlive(pidfd) != nil {
			_ = unix.Close(pidfd)
			return -1, 0, 0, errors.New("coordinator start identity changed during pidfd custody transfer")
		}
		return pidfd, pid, start, nil
	}
	return -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverTimeout)
}

func checkpointLocalObserverReadCoordinatorCompletion(file *os.File, nonce string, timeout time.Duration) error {
	if file == nil || len(nonce) != 32 || timeout <= 0 {
		return errors.New("invalid coordinator completion receiver")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(file.Fd()), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 25)
		if err != nil {
			if checkpointLocalObserverPollInterrupted(err) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		payload := make([]byte, 128)
		oob := make([]byte, unix.CmsgSpace(4))
		n, oobn, flags, _, err := unix.Recvmsg(int(file.Fd()), payload, oob, unix.MSG_CMSG_CLOEXEC|unix.MSG_DONTWAIT)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		if flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || n != len("COMPLETE:")+len(nonce) || oobn != 0 || string(payload[:n]) != "COMPLETE:"+nonce {
			return errors.New("coordinator durable-completion packet has invalid nonce or ancillary framing")
		}
		return nil
	}
	return errors.New("coordinator durable-completion packet deadline expired")
}

func checkpointLocalObserverVerifyParentDeathUnit(fixture *checkpointLocalObserverFixtureUnit, live bool) error {
	if fixture == nil || fixture.pid <= 1 || fixture.start == 0 || fixture.pidfd < 0 || !checkpointLocalObserverValidInvocation(fixture.invocation) {
		return errors.New("fixture unit identity tuple or pidfd is incomplete")
	}
	state, err := checkpointLocalObserverShowFixtureUnit(fixture.name)
	if !live {
		if err != nil || state["LoadState"] != "not-found" {
			return errors.New("exact fixture unit is not absent")
		}
		if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 10*time.Millisecond); err != nil {
			return err
		}
		time.Sleep(25 * time.Millisecond)
		stateAgain, err := checkpointLocalObserverShowFixtureUnit(fixture.name)
		if err != nil || stateAgain["LoadState"] != "not-found" {
			return errors.New("exact fixture unit absence was not stable across two held-pidfd checks")
		}
		return checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 10*time.Millisecond)
	}
	if err != nil || !checkpointLocalObserverFixtureStateMatches(state, fixture.name, fixture.pid, fixture.invocation, fixture.cgroup) {
		return errors.New("exact fixture unit invocation/mainpid/cgroup tuple changed")
	}
	if state["ActiveState"] != "active" {
		return errors.New("exact fixture unit is not active immediately before parent-death proof")
	}
	start, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
	if err != nil || start != fixture.start || checkpointLocalObserverPidfdTarget(fixture.pidfd) != fixture.pid || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("exact fixture unit held pidfd/start identity is not live")
	}
	stateAgain, err := checkpointLocalObserverShowFixtureUnit(fixture.name)
	if err != nil || stateAgain["ActiveState"] != "active" || !checkpointLocalObserverFixtureStateMatches(stateAgain, fixture.name, fixture.pid, fixture.invocation, fixture.cgroup) {
		return errors.New("exact fixture unit changed during pidfd/start identity join")
	}
	startAgain, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
	if err != nil || startAgain != fixture.start || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("exact fixture unit became stale during currentness recheck")
	}
	return nil
}

func checkpointLocalObserverStopParentDeathUnit(fixture *checkpointLocalObserverFixtureUnit) error {
	if err := checkpointLocalObserverVerifyParentDeathUnit(fixture, true); err != nil {
		return err
	}
	state, err := checkpointLocalObserverShowFixtureUnit(fixture.name)
	if err != nil || state["ActiveState"] != "active" || !checkpointLocalObserverFixtureStateMatches(state, fixture.name, fixture.pid, fixture.invocation, fixture.cgroup) {
		return errors.New("fixture unit was not loaded immediately before exact parent-death signal")
	}
	start, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
	if err != nil || start != fixture.start || checkpointLocalObserverPidfdTarget(fixture.pidfd) != fixture.pid || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("fixture MainPID/current pidfd changed immediately before exact parent-death signal")
	}
	if err := unix.PidfdSendSignal(fixture.pidfd, unix.SIGTERM, nil, 0); err != nil {
		return fmt.Errorf("required exact held-pidfd termination signal was not delivered: %w", err)
	}
	if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 5*time.Second); err != nil {
		return err
	}
	return checkpointLocalObserverVerifyParentDeathUnit(fixture, false)
}

func checkpointLocalObserverPidfdTarget(pidfd int) int {
	if pidfd < 0 {
		return -1
	}
	contents, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", strconv.Itoa(pidfd)))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if strings.HasPrefix(line, "Pid:") {
			pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Pid:")))
			if err == nil {
				return pid
			}
		}
	}
	return -1
}

func checkpointLocalObserverProcessCgroup(pid int) (string, error) {
	if pid <= 1 {
		return "", errors.New("invalid process for cgroup observation")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cgroup"))
	if err != nil || len(data) == 0 || len(data) > 4096 {
		return "", errors.New("process cgroup file is absent or exceeds its bound")
	}
	var found string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			if found != "" {
				return "", errors.New("duplicate unified process cgroup row")
			}
			found = strings.TrimPrefix(line, "0::")
		}
	}
	if found == "" || !filepath.IsAbs(found) || strings.Contains(found, "..") {
		return "", errors.New("process has no canonical unified cgroup path")
	}
	return found, nil
}

func checkpointLocalObserverMonotonicNS() (int64, error) {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil || value.Sec < 0 || value.Nsec < 0 || value.Nsec >= int64(time.Second) {
		return 0, errors.New("monotonic clock observation failed")
	}
	return value.Sec*int64(time.Second) + value.Nsec, nil
}

func TestCheckpointLocalObserverKernelClientChild(t *testing.T) {
	role := os.Getenv(checkpointLocalObserverKernelChild)
	if role == "" || role != "client" && role != "wrong-peer" && role != "wrong-gid" && role != "wrong-key" && role != "wrong-nonce" && role != "worker-exit" && role != "worker-replaced" && role != "key-substitution" && role != "identity-substitution" && role != "namespace-substitution" && role != "public-key-read-positive" && role != "public-key-permission-denied" {
		return
	}
	root := os.Getenv("CHECKPOINT_LOCAL_OBSERVER_FIXTURE_ROOT")
	config := checkpointLocalObserverKernelConfigFromEnv(root)
	if role == "public-key-read-positive" {
		rootInfo, rootErr := os.Lstat(config.trustRoot)
		var rootStat *syscall.Stat_t
		rootOK := false
		if rootErr == nil {
			rootStat, rootOK = rootInfo.Sys().(*syscall.Stat_t)
		}
		public, pin, err := checkpointLocalObserverReadPublicKey(config)
		if rootErr != nil || !rootOK || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootStat.Uid != 0 || rootInfo.Mode().Perm() != 0711 || err != nil || len(public) != ed25519.PublicKeySize || pin.uid != 0 || pin.gid != checkpointLocalObserverExpectedGroup(config.nodeGroup) || pin.mode != 0640 || pin.stat.Nlink != 1 || pin.fd < 0 {
			if err == nil {
				checkpointLocalObserverCloseFilePin(pin)
			}
			t.Fatal("unprivileged public-key read did not preserve exact search-root and leaf pins")
		}
		checkpointLocalObserverCloseFilePin(pin)
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_READ_POSITIVE__")
		return
	}
	if role == "public-key-permission-denied" {
		if _, pin, err := checkpointLocalObserverReadPublicKey(config); err == nil {
			checkpointLocalObserverCloseFilePin(pin)
			t.Fatal("unprivileged public-key read succeeded through a denied permission control")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_PERMISSION_DENIED__")
		return
	}
	if role == "wrong-peer" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("wrong-UID client received a signed response from the root broker")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WRONG_PEER_DENIED__")
		return
	}
	if role == "wrong-gid" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("wrong-GID client received a signed response from the root broker")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WRONG_GID_DENIED__")
		return
	}
	if role == "wrong-key" || role == "wrong-nonce" {
		nonceRaw := make([]byte, checkpointLocalObserverNonceBytes)
		if _, err := rand.Read(nonceRaw); err != nil {
			t.Fatal(err)
		}
		nonce := hex.EncodeToString(nonceRaw)
		wire := checkpointLocalObserverKernelExchange(t, config, nonce)
		public, pin, err := checkpointLocalObserverReadPublicKey(config)
		if err != nil {
			t.Fatal(err)
		}
		defer checkpointLocalObserverCloseFilePin(pin)
		if _, err := checkpointLocalObserverVerify(wire, public, nonce, time.Now().UTC()); err != nil {
			t.Fatalf("known root-signed IPC response was not valid before negative verification: %v", err)
		}
		if role == "wrong-key" {
			wrongPublic, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := checkpointLocalObserverVerify(wire, wrongPublic, nonce, time.Now().UTC()); err == nil {
				t.Fatal("root-signed IPC response verified under a wrong key")
			}
			fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WRONG_KEY_DENIED__")
		} else {
			wrongNonce := strings.Repeat("f", len(nonce))
			if wrongNonce == nonce {
				wrongNonce = strings.Repeat("e", len(nonce))
			}
			if _, err := checkpointLocalObserverVerify(wire, public, wrongNonce, time.Now().UTC()); err == nil {
				t.Fatal("root-signed IPC response verified under a different request nonce")
			}
			fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WRONG_NONCE_DENIED__")
		}
		return
	}
	if role == "worker-replaced" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("stale fixed worker association was signed after a replacement worker started")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WORKER_REPLACED_DENIED__")
		return
	}
	if role == "key-substitution" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("broker accepted a substituted public-key path")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_KEY_SUBSTITUTION_DENIED__")
		return
	}
	if role == "worker-exit" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("broker signed an association after the fixed worker exited")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_WORKER_EXIT_DENIED__")
		return
	}
	if role == "identity-substitution" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("client accepted a signed caller executable identity substitution")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_IDENTITY_SUBSTITUTION_DENIED__")
		return
	}
	if role == "namespace-substitution" {
		if _, err := checkpointLocalObserverObserveWithConfig(context.Background(), config); err == nil {
			t.Fatal("client accepted a worker namespace substitution")
		}
		fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_NAMESPACE_SUBSTITUTION_DENIED__")
		return
	}
	workerPID, _ := strconv.Atoi(os.Getenv("CHECKPOINT_LOCAL_OBSERVER_FIXTURE_WORKER_PID"))
	for _, suffix := range []string{"exe", "maps", "ns/pid"} {
		file, err := os.Open(filepath.Join("/proc", strconv.Itoa(workerPID), suffix))
		if err == nil {
			_ = file.Close()
			t.Fatalf("unprivileged observer opened protected root worker proc path %s", suffix)
		}
	}
	if _, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(workerPID), "stat")); err != nil {
		t.Fatalf("unprivileged observer could not read public worker start record: %v", err)
	}
	result, err := checkpointLocalObserverObserveWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Caller.UID != 65534 || result.Caller.GID != checkpointLocalObserverExpectedGroup(config.nodeGroup) || result.Worker.UID != 0 || result.Worker.PID != workerPID {
		t.Fatal("signed response did not preserve caller/root-worker roles")
	}
	fmt.Println("__CHECKPOINT_LOCAL_OBSERVER_CLIENT_POSITIVE__")
}

func TestCheckpointLocalObserverKernelWorkerChild(t *testing.T) {
	if os.Getenv(checkpointLocalObserverKernelChild) != "worker" {
		return
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestCheckpointLocalObserverKernelServerChild(t *testing.T) {
	if os.Getenv(checkpointLocalObserverKernelChild) != "server" {
		return
	}
	root := os.Getenv("CHECKPOINT_LOCAL_OBSERVER_FIXTURE_ROOT")
	config := checkpointLocalObserverKernelConfigFromEnv(root)
	config.fixturePayloadMutator = func(payload *checkpointLocalObserverPayload) (string, error) {
		phase, phaseErr := checkpointLocalObserverKernelReadPhase(root)
		if phaseErr != nil || phase == "" {
			return "", phaseErr
		}
		switch phase {
		case "identity-substitution":
			payload.Caller.ExecutableSHA256 = strings.Repeat("b", 64)
			return "identity", nil
		case "namespace-substitution":
			payload.Worker.PIDNamespaceInode++
			return "namespace", nil
		default:
			return "", fmt.Errorf("unknown fixture mutation phase %q", phase)
		}
	}
	config.fixtureMutationResult = func(kind string, signed bool) error {
		if kind == "identity" && signed {
			return checkpointLocalObserverKernelWriteMarker(root, "identity-substitution.result", "identity signed\n")
		}
		if kind == "namespace" && !signed {
			return checkpointLocalObserverKernelWriteMarker(root, "namespace-substitution.result", "sign rejected\n")
		}
		return fmt.Errorf("fixture signer reached unexpected %s mutation result signed=%t", kind, signed)
	}
	workerPID, err := strconv.Atoi(os.Getenv("CHECKPOINT_LOCAL_OBSERVER_FIXTURE_WORKER_PID"))
	if err != nil || workerPID <= 1 {
		t.Fatal("fixture server received an invalid worker PID")
	}
	group, err := user.LookupGroup(config.nodeGroup)
	if err != nil {
		t.Fatal(err)
	}
	groupNumber, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || groupNumber == 0 {
		t.Fatalf("invalid existing fixture group GID %q", group.Gid)
	}
	groupID := uint32(groupNumber)
	wrongGID := checkpointLocalObserverFixtureWrongGID(groupID)
	if err := checkpointLocalObserverAssertBrokerCapabilityPosture(groupID); err != nil {
		t.Fatal(err)
	}
	if err := checkpointLocalObserverKernelWriteMarker(root, "broker-capability.marker", "CAP_SYS_PTRACE_ONLY_ROOT_VRAM_GROUP_NNP\n"); err != nil {
		t.Fatal(err)
	}
	worker, err := checkpointLocalObserverOpenCurrent(workerPID)
	if err != nil {
		t.Fatalf("hold fixture worker identity: %v", err)
	}
	workerStart, workerNamespace := worker.start, worker.namespace
	worker.close()
	config.peerDenied = func(uid, gid uint32) error {
		name, expectedUID, expectedGID := "peer-denied-uid.marker", uint32(65533), groupID
		if uid == 65534 && gid == wrongGID {
			name, expectedUID, expectedGID = "peer-denied-gid.marker", uint32(65534), wrongGID
		}
		if uid != expectedUID || gid != expectedGID {
			return errors.New("observed peer denial did not match the declared UID/GID control")
		}
		return checkpointLocalObserverKernelWriteMarker(root, name, fmt.Sprintf("SO_PEERCRED_POLICY_DENIED uid=%d gid=%d\n", uid, gid))
	}
	config.pinDenied = func() error {
		return checkpointLocalObserverKernelWriteMarker(root, "key-substitution-denied.marker", "HELD_ROOT_KEY_PATH_SUBSTITUTION_DENIED\n")
	}
	config.collect = func(ctx context.Context) (CheckpointManagedBinding, error) {
		if err := ctx.Err(); err != nil {
			return CheckpointManagedBinding{}, err
		}
		current, err := checkpointLocalObserverOpenCurrent(workerPID)
		if err != nil {
			marker, contents, markerErr := checkpointLocalObserverKernelStaleMarker(root)
			if markerErr == nil {
				markerErr = checkpointLocalObserverKernelWriteMarker(root, marker, contents)
			}
			if markerErr != nil {
				return CheckpointManagedBinding{}, errors.Join(err, markerErr)
			}
			return CheckpointManagedBinding{}, err
		}
		defer current.close()
		if current.uid != 0 || current.start != workerStart || current.namespace != workerNamespace {
			marker, contents, markerErr := checkpointLocalObserverKernelStaleMarker(root)
			if markerErr == nil {
				markerErr = checkpointLocalObserverKernelWriteMarker(root, marker, contents)
			}
			if markerErr != nil {
				return CheckpointManagedBinding{}, errors.Join(errors.New("root fixture worker identity changed"), markerErr)
			}
			return CheckpointManagedBinding{}, errors.New("root fixture worker identity changed")
		}
		return checkpointLocalObserverFixtureBinding(current), nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	if err := checkpointLocalObserverRunWithConfig(ctx, config); err != nil && err != context.Canceled {
		t.Fatal(err)
	}
}

func checkpointLocalObserverAssertBrokerCapabilityPosture(groupID uint32) error {
	if os.Geteuid() != 0 || uint32(os.Getgid()) != groupID {
		return errors.New("fixture broker does not match fixed root:vram-governor service identity")
	}
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			fields[parts[0]] = strings.TrimSpace(parts[1])
		}
	}
	const capSysPtrace = uint64(1 << 19)
	for _, field := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, parseErr := strconv.ParseUint(fields[field], 16, 64)
		if parseErr != nil || value != capSysPtrace {
			return fmt.Errorf("fixture broker %s is not exactly CAP_SYS_PTRACE", field)
		}
	}
	ids := strings.Fields(fields["Gid"])
	uids := strings.Fields(fields["Uid"])
	if len(ids) != 4 || ids[0] != strconv.FormatUint(uint64(groupID), 10) || len(uids) != 4 || uids[0] != "0" || fields["NoNewPrivs"] != "1" {
		return errors.New("fixture broker group or no-new-privileges posture differs from the fixed service")
	}
	return nil
}

func checkpointLocalObserverAssertEffectiveBrokerUnit(fixture *checkpointLocalObserverFixtureUnit, groupID uint32) error {
	if fixture == nil || !fixture.owned || fixture.pid <= 1 || fixture.pidfd < 0 || !checkpointLocalObserverValidInvocation(fixture.invocation) || fixture.cgroup == "" {
		return errors.New("broker observer lacks the exact held unit, pidfd, invocation, and cgroup")
	}
	state, err := checkpointLocalObserverShowFixtureUnit(fixture.name)
	if err != nil || !checkpointLocalObserverFixtureStateMatches(state, fixture.name, fixture.pid, fixture.invocation, fixture.cgroup) || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("broker systemd unit or pidfd no longer matches the held identity")
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(fixture.pid), "status"))
	if err != nil || len(status) == 0 || len(status) > 64<<10 {
		return errors.New("broker proc status is unavailable or outside its fixed bound")
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(string(status), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, exists := fields[key]; exists {
			return errors.New("broker proc status contains a duplicate identity field")
		}
		fields[key] = strings.TrimSpace(value)
	}
	const expectedCapability = uint64(1 << 19)
	uid, gid := strings.Fields(fields["Uid"]), strings.Fields(fields["Gid"])
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, parseErr := strconv.ParseUint(fields[key], 16, 64)
		if parseErr != nil || value != expectedCapability {
			return fmt.Errorf("broker proc %s is not exactly CAP_SYS_PTRACE", key)
		}
	}
	expectedGID := strconv.FormatUint(uint64(groupID), 10)
	if len(uid) != 4 || len(gid) != 4 || fields["NoNewPrivs"] != "1" || fields["Seccomp"] != "2" {
		return errors.New("broker proc UID/GID, NoNewPrivs, or active seccomp filter differs from the fixed service")
	}
	for index := 0; index < 4; index++ {
		if uid[index] != "0" || gid[index] != expectedGID {
			return errors.New("broker proc real/effective/saved/filesystem UID or GID differs from the fixed service")
		}
	}
	filter, err := checkpointLocalObserverBoundedCommand(3*time.Second, "/usr/bin/systemctl", "show", "--no-pager", "--value", "--property=SystemCallFilter", fixture.name)
	filter = strings.TrimSpace(filter)
	if err != nil || !strings.HasPrefix(filter, "~") {
		return errors.New("effective fixed broker SystemCallFilter property is missing or broader than the reviewed denylist")
	}
	denied := strings.Fields(strings.TrimPrefix(filter, "~"))
	deniedSet := make(map[string]bool, len(denied))
	for _, syscallName := range denied {
		if syscallName == "" || deniedSet[syscallName] {
			return errors.New("effective fixed broker SystemCallFilter property has an empty or duplicate syscall")
		}
		deniedSet[syscallName] = true
	}
	if len(deniedSet) != 2 || !deniedSet["ptrace"] || !deniedSet["process_vm_writev"] {
		return errors.New("effective fixed broker SystemCallFilter property differs from the exact denylist")
	}
	currentStart, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
	stateAgain, stateErr := checkpointLocalObserverShowFixtureUnit(fixture.name)
	if startErr != nil || currentStart != fixture.start || stateErr != nil || !checkpointLocalObserverFixtureStateMatches(stateAgain, fixture.name, fixture.pid, fixture.invocation, fixture.cgroup) || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("broker process or unit identity changed during effective security-property observation")
	}
	return nil
}

func checkpointLocalObserverKernelWriteMarker(root, name, contents string) error {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, "/\\\x00") {
		return errors.New("invalid private fixture marker name")
	}
	file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	writeErr := checkpointLocalObserverWriteFull(file, []byte(contents))
	if writeErr == nil {
		writeErr = file.Sync()
	}
	return errors.Join(writeErr, file.Close())
}

func checkpointLocalObserverKernelReadPhase(root string) (string, error) {
	var found string
	for _, item := range []struct{ name, value string }{
		{"identity-substitution.phase", "identity-substitution"},
		{"namespace-substitution.phase", "namespace-substitution"},
		{"worker-exit.phase", "worker-exit"},
		{"worker-replaced.phase", "worker-replaced"},
	} {
		markerPath := filepath.Join(root, item.name)
		file, err := os.OpenFile(markerPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		before, statErr := file.Stat()
		var pinned *syscall.Stat_t
		if statErr == nil {
			pinned, _ = before.Sys().(*syscall.Stat_t)
		}
		if statErr != nil || pinned == nil || pinned.Uid != 0 || !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > 64 {
			_ = file.Close()
			return "", errors.New("fixture phase marker metadata is not trusted")
		}
		contents, readErr := io.ReadAll(io.LimitReader(file, 65))
		after, afterErr := file.Stat()
		closeErr := file.Close()
		current, pathErr := os.Lstat(markerPath)
		var currentStat *syscall.Stat_t
		currentOK := false
		if pathErr == nil {
			currentStat, currentOK = current.Sys().(*syscall.Stat_t)
		}
		if readErr != nil || afterErr != nil || closeErr != nil || pathErr != nil || !currentOK || currentStat.Dev != pinned.Dev || currentStat.Ino != pinned.Ino || after.Size() != before.Size() || string(contents) != item.value+"\n" {
			return "", errors.New("fixture phase marker changed while read")
		}
		if found != "" {
			return "", errors.New("multiple fixture mutation phases are active")
		}
		found = item.value
	}
	return found, nil
}

func checkpointLocalObserverKernelStaleMarker(root string) (string, string, error) {
	phase, err := checkpointLocalObserverKernelReadPhase(root)
	if err != nil {
		return "", "", err
	}
	switch phase {
	case "worker-exit":
		return "worker-exit-denied.marker", "FIXED_WORKER_EXIT_NOT_CURRENT\n", nil
	case "worker-replaced":
		return "replacement-worker-denied.marker", "FIXED_WORKER_REPLACEMENT_NOT_CURRENT\n", nil
	default:
		return "stale-worker-denied.marker", "FIXED_WORKER_PIDFD_OR_START_NOT_CURRENT\n", nil
	}
}

func checkpointLocalObserverKernelRequireMutationMarker(root, name, want string) error {
	got, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		return err
	}
	if string(got) != want {
		return fmt.Errorf("fixture mutation marker %s differs from expected", name)
	}
	return nil
}

func checkpointLocalObserverKernelRemoveMarker(root, name, want string) error {
	if err := checkpointLocalObserverKernelRequireMutationMarker(root, name, want); err != nil {
		return err
	}
	return os.Remove(filepath.Join(root, name))
}

func checkpointLocalObserverKernelConfigFromEnv(root string) checkpointLocalObserverRuntimeConfig {
	return checkpointLocalObserverRuntimeConfig{
		socketPath: filepath.Join(root, "run", "observer.sock"), socketDir: filepath.Join(root, "run"),
		policyPath: filepath.Join(root, "conf", "policy.json"), privatePath: filepath.Join(root, "signing", "observer.key"), publicPath: filepath.Join(root, "conf", "observer.pub"),
		nodeGroup: os.Getenv("CHECKPOINT_LOCAL_OBSERVER_FIXTURE_GROUP"), trustRoot: root, fixtureAnchor: true,
	}
}

func checkpointLocalObserverKernelRunClient(t *testing.T, root string, config checkpointLocalObserverRuntimeConfig, workerPID int, uid, gid uint32) string {
	t.Helper()
	role := "client"
	if uid != 65534 {
		role = "wrong-peer"
	}
	return checkpointLocalObserverKernelRunClientMode(t, root, config, workerPID, role, uid, gid)
}

func checkpointLocalObserverKernelRunClientMode(t *testing.T, root string, config checkpointLocalObserverRuntimeConfig, workerPID int, role string, uid, gid uint32) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		t.Fatal("fixture client executable path is not absolute")
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestCheckpointLocalObserverKernelClientChild$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", checkpointLocalObserverKernelChild + "=" + role, "CHECKPOINT_LOCAL_OBSERVER_FIXTURE_ROOT=" + root, "CHECKPOINT_LOCAL_OBSERVER_FIXTURE_GROUP=" + config.nodeGroup, "CHECKPOINT_LOCAL_OBSERVER_FIXTURE_WORKER_PID=" + strconv.Itoa(workerPID)}
	credential := &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true}
	if role == "wrong-gid" {
		credential.Gid = gid
		credential.Groups = []uint32{checkpointLocalObserverExpectedGroup(config.nodeGroup)}
		credential.NoSetGroups = false
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	cmd.WaitDelay = time.Second
	output := &checkpointLocalObserverLimitedBuffer{}
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = output, output
	err = cmd.Run()
	if output.overflow {
		t.Fatalf("unprivileged client helper exceeded output bound")
	}
	if ctx.Err() != nil {
		t.Fatalf("bounded unprivileged client helper timed out: %v", ctx.Err())
	}
	if err != nil {
		t.Fatalf("bounded unprivileged client helper failed: %v (%s)", err, boundedLocalObserverText(output.data))
	}
	return boundedLocalObserverText(output.data)
}

func checkpointLocalObserverKernelExchange(t *testing.T, config checkpointLocalObserverRuntimeConfig, nonce string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	request, err := checkpointLocalObserverCanonicalRequest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	connRaw, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "unix", config.socketPath)
	if err != nil {
		t.Fatalf("connect to fixed observer for signed-response control: %v", err)
	}
	conn := connRaw.(*net.UnixConn)
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		t.Fatal(err)
	}
	uid, gid, pid, err := checkpointLocalObserverPeer(conn)
	if err != nil || uid != 0 || gid != checkpointLocalObserverExpectedGroup(config.nodeGroup) || pid <= 1 {
		t.Fatalf("raw control reached an unexpected broker SO_PEERCRED: uid=%d gid=%d pid=%d err=%v", uid, gid, pid, err)
	}
	broker, err := checkpointLocalObserverOpenCrossUID(pid)
	if err != nil {
		t.Fatalf("hold root broker for signed-response control: %v", err)
	}
	defer broker.close()
	if err := checkpointLocalObserverWriteFull(conn, request); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	wire, err := io.ReadAll(io.LimitReader(conn, checkpointLocalObserverMaxFrame+1))
	if err != nil || len(wire) == 0 || len(wire) > checkpointLocalObserverMaxFrame {
		t.Fatalf("read bounded signed-response control: bytes=%d err=%v", len(wire), err)
	}
	if err := checkpointLocalPIDFDAlive(broker.pidfd); err != nil {
		t.Fatalf("broker exited during signed-response control: %v", err)
	}
	return wire
}

func checkpointLocalObserverKernelSubstitutePublicKey(root, publicPath string, groupID uint32) error {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return err
	}
	rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootStat.Uid != 0 {
		return errors.New("private fixture root is not pinned before key substitution")
	}
	parentInfo, err := os.Lstat(filepath.Dir(publicPath))
	if err != nil {
		return err
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentStat.Uid != 0 || parentStat.Gid != groupID {
		return errors.New("public-key parent is not pinned before substitution")
	}
	original, err := os.Lstat(publicPath)
	if err != nil {
		return err
	}
	originalStat, ok := original.Sys().(*syscall.Stat_t)
	if !ok || original.Mode()&os.ModeSymlink != 0 || !original.Mode().IsRegular() || originalStat.Uid != 0 || originalStat.Gid != groupID || originalStat.Nlink != 1 || original.Mode().Perm() != 0640 {
		return errors.New("public key before substitution is not the pinned fixture file")
	}
	_, replacementPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	replacementPublic := replacementPrivate.Public().(ed25519.PublicKey)
	staged := publicPath + ".replacement"
	backup := publicPath + ".original"
	for _, candidate := range []string{staged, backup} {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			return errors.New("public-key substitution staging path already exists or is uncertain")
		}
	}
	file, err := os.OpenFile(staged, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	writeErr := checkpointLocalObserverWriteFull(file, replacementPublic)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := os.Chown(staged, 0, int(groupID)); err != nil {
		return err
	}
	if err := os.Chmod(staged, 0640); err != nil {
		return err
	}
	if err := os.Rename(publicPath, backup); err != nil {
		return err
	}
	if err := os.Rename(staged, publicPath); err != nil {
		return fmt.Errorf("publish exact public-key substitute; original retained at %s: %w", backup, err)
	}
	current, err := os.Lstat(publicPath)
	if err != nil {
		return err
	}
	currentStat, ok := current.Sys().(*syscall.Stat_t)
	if !ok || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || currentStat.Dev != originalStat.Dev || currentStat.Ino == originalStat.Ino || currentStat.Uid != 0 || currentStat.Gid != groupID || currentStat.Nlink != 1 || current.Size() != int64(ed25519.PublicKeySize) || current.Mode().Perm() != 0640 {
		return errors.New("published root public-key substitute has an unexpected inode or mode")
	}
	currentRoot, err := os.Lstat(root)
	if err != nil {
		return err
	}
	currentRootStat, ok := currentRoot.Sys().(*syscall.Stat_t)
	if !ok || currentRootStat.Dev != rootStat.Dev || currentRootStat.Ino != rootStat.Ino || currentRootStat.Uid != rootStat.Uid || currentRoot.Mode()&os.ModeSymlink != 0 {
		return errors.New("fixture root identity changed during public-key substitution")
	}
	currentParent, err := os.Lstat(filepath.Dir(publicPath))
	if err != nil {
		return err
	}
	currentParentStat, ok := currentParent.Sys().(*syscall.Stat_t)
	if !ok || currentParentStat.Dev != parentStat.Dev || currentParentStat.Ino != parentStat.Ino || currentParentStat.Uid != parentStat.Uid || currentParentStat.Gid != parentStat.Gid || currentParent.Mode()&os.ModeSymlink != 0 {
		return errors.New("public-key parent identity changed during substitution")
	}
	return nil
}

func checkpointLocalObserverStartFixtureUnit(t *testing.T, role, root, group string, workerPID int) (*checkpointLocalObserverFixtureUnit, error) {
	t.Helper()
	if role != "worker" && role != "server" {
		return nil, errors.New("unknown fixed fixture unit role")
	}
	if role == "server" && workerPID <= 1 {
		return nil, errors.New("fixture server requires the exact worker PID")
	}
	unitBytes := make([]byte, 12)
	if _, err := rand.Read(unitBytes); err != nil {
		return nil, err
	}
	unit := "checkpoint-local-observer-fixture-" + role + "-" + hex.EncodeToString(unitBytes) + ".service"
	if state, err := checkpointLocalObserverShowFixtureUnit(unit); err != nil {
		return nil, err
	} else if state["LoadState"] != "not-found" {
		return nil, fmt.Errorf("random fixture unit name unexpectedly exists: %s", unit)
	}
	owned := &checkpointLocalObserverFixtureUnit{name: unit, owned: true, pidfd: -1}
	childTest := "TestCheckpointLocalObserverKernelWorkerChild"
	if role == "server" {
		childTest = "TestCheckpointLocalObserverKernelServerChild"
	}
	args := []string{"--quiet", "--collect", "--unit", unit, "--property=Type=exec", "--property=KillMode=control-group", "--property=RuntimeMaxSec=200s", "--property=TimeoutStopSec=5s", "--property=Restart=no", "--property=User=root", "--property=Group=" + group, "--setenv=" + checkpointLocalObserverKernelChild + "=" + role, "--setenv=CHECKPOINT_LOCAL_OBSERVER_FIXTURE_ROOT=" + root, "--setenv=CHECKPOINT_LOCAL_OBSERVER_FIXTURE_GROUP=" + group}
	if role == "server" {
		args = append(args, "--property=CapabilityBoundingSet=CAP_SYS_PTRACE", "--property=AmbientCapabilities=CAP_SYS_PTRACE", "--property=NoNewPrivileges=yes", "--property=SystemCallFilter=~ptrace process_vm_writev", "--setenv=CHECKPOINT_LOCAL_OBSERVER_FIXTURE_WORKER_PID="+strconv.Itoa(workerPID))
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return nil, errors.New("fixture test executable path is not absolute")
	}
	args = append(args, "--", executable, "-test.run=^"+childTest+"$")
	startedMonoNS, monoErr := checkpointLocalObserverMonotonicNS()
	if monoErr != nil || startedMonoNS <= 0 {
		return owned, errors.New("fixture unit start monotonic clock is unavailable")
	}
	if _, err := checkpointLocalObserverBoundedCommand(8*time.Second, "/usr/bin/systemd-run", args...); err != nil {
		return owned, fmt.Errorf("start exact transient fixture unit %s: %w", unit, err)
	}
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		state, err := checkpointLocalObserverShowFixtureUnit(unit)
		if err == nil && state["LoadState"] == "loaded" && state["ActiveState"] == "active" {
			pid, parseErr := strconv.Atoi(state["MainPID"])
			if parseErr != nil || pid <= 1 || !checkpointLocalObserverValidInvocation(state["InvocationID"]) || !strings.HasPrefix(state["ControlGroup"], "/system.slice/"+strings.TrimSuffix(unit, ".service")) {
				return owned, fmt.Errorf("transient unit %s has invalid main PID or cgroup", unit)
			}
			pidfd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				return owned, fmt.Errorf("hold transient unit main PID: %w", err)
			}
			start, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
			stateAgain, stateErr := checkpointLocalObserverShowFixtureUnit(unit)
			aliveErr := checkpointLocalPIDFDAlive(pidfd)
			if startErr == nil && start != 0 && stateErr == nil && checkpointLocalObserverFixtureStateMatches(stateAgain, unit, pid, state["InvocationID"], state["ControlGroup"]) && aliveErr == nil {
				owned.pid, owned.start, owned.startedAt, owned.invocation, owned.cgroup, owned.pidfd = pid, start, startedMonoNS, state["InvocationID"], state["ControlGroup"], pidfd
				return owned, nil
			}
			_ = unix.Close(pidfd)
		}
		time.Sleep(25 * time.Millisecond)
	}
	return owned, fmt.Errorf("transient fixture unit %s did not become pinned active within its bound; preserving ambiguous unit name", unit)
}

func checkpointLocalObserverStopFixtureUnit(fixture *checkpointLocalObserverFixtureUnit) error {
	if fixture == nil || !fixture.owned {
		return nil
	}
	unit := fixture.name
	if !strings.HasPrefix(unit, "checkpoint-local-observer-fixture-") || !strings.HasSuffix(unit, ".service") || strings.ContainsAny(unit, "/\\\x00") || fixture.pid <= 1 || fixture.start == 0 || fixture.invocation == "" || fixture.cgroup == "" || fixture.pidfd < 0 {
		return errors.New("refusing non-fixture transient unit name")
	}
	state, err := checkpointLocalObserverShowFixtureUnit(unit)
	if err != nil {
		return err
	}
	if state["LoadState"] == "not-found" {
		if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 2*time.Second); err != nil {
			return err
		}
		state, err = checkpointLocalObserverShowFixtureUnit(unit)
		if err != nil || state["LoadState"] != "not-found" {
			return errors.New("exact fixture unit absence was not stable after held-pidfd exit")
		}
		fixture.owned = false
		return nil
	}
	if !checkpointLocalObserverFixtureStateMatches(state, unit, fixture.pid, fixture.invocation, fixture.cgroup) {
		return errors.New("fixture unit invocation, MainPID, or cgroup changed; preserving it")
	}
	currentStart, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
	if err != nil || currentStart != fixture.start || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
		return errors.New("fixture process start or held pidfd changed; preserving unit")
	}
	if err := unix.PidfdSendSignal(fixture.pidfd, unix.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
		return fmt.Errorf("signal exact held fixture process: %w", err)
	}
	if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 5*time.Second); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := checkpointLocalObserverShowFixtureUnit(unit)
		if err == nil && state["LoadState"] == "not-found" {
			if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, time.Second); err != nil {
				return err
			}
			state, err = checkpointLocalObserverShowFixtureUnit(unit)
			if err != nil || state["LoadState"] != "not-found" {
				return errors.New("exact fixture unit unload was not stable after held-pidfd exit")
			}
			fixture.owned = false
			return nil
		}
		if err == nil && state["LoadState"] == "loaded" && !checkpointLocalObserverFixtureStateMatches(state, unit, fixture.pid, fixture.invocation, fixture.cgroup) {
			return errors.New("fixture unit identity drifted during exact pidfd cleanup")
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("exact fixture unit %s did not unload after held-pidfd termination", unit)
}

func checkpointLocalObserverWaitFixtureUnit(fixture *checkpointLocalObserverFixtureUnit) error {
	if fixture == nil || !fixture.owned {
		return errors.New("fixture unit identity was not owned")
	}
	unit := fixture.name
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		state, err := checkpointLocalObserverShowFixtureUnit(unit)
		if err == nil && state["LoadState"] == "not-found" {
			if err := checkpointLocalObserverWaitPidfdExited(fixture.pidfd, 2*time.Second); err != nil {
				return err
			}
			state, err = checkpointLocalObserverShowFixtureUnit(unit)
			if err != nil || state["LoadState"] != "not-found" {
				return errors.New("exact fixture unit absence changed after held worker reap")
			}
			return nil
		}
		if err == nil && state["LoadState"] == "loaded" && !checkpointLocalObserverFixtureStateMatches(state, unit, fixture.pid, fixture.invocation, fixture.cgroup) {
			return errors.New("fixture unit identity changed while awaiting held worker exit")
		}
		if err == nil && state["LoadState"] == "loaded" {
			start, startErr := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(fixture.pid)), fixture.pid)
			if startErr != nil || start != fixture.start || checkpointLocalPIDFDAlive(fixture.pidfd) != nil {
				return errors.New("fixture MainPID start or pidfd changed while awaiting unit exit")
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("exact fixture unit %s exceeded its lifetime bound", unit)
}

func checkpointLocalObserverFixtureStateMatches(state map[string]string, unit string, pid int, invocation, cgroup string) bool {
	return state["LoadState"] == "loaded" && state["MainPID"] == strconv.Itoa(pid) && checkpointLocalObserverValidInvocation(invocation) && state["InvocationID"] == invocation && state["ControlGroup"] == cgroup && strings.HasPrefix(cgroup, "/system.slice/"+strings.TrimSuffix(unit, ".service"))
}

func checkpointLocalObserverValidInvocation(invocation string) bool {
	decoded, err := hex.DecodeString(invocation)
	return err == nil && len(decoded) == 16 && hex.EncodeToString(decoded) == invocation && invocation != strings.Repeat("0", 32)
}

func checkpointLocalObserverWaitPidfdExited(pidfd int, timeout time.Duration) error {
	if pidfd < 0 {
		return errors.New("fixture process has no held pidfd for reap confirmation")
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		ready, err := unix.Poll(poll, 25)
		if err != nil {
			if checkpointLocalObserverPollInterrupted(err) {
				continue
			}
			return err
		}
		if ready == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 || poll[0].Revents & ^int16(unix.POLLIN|unix.POLLHUP) != 0 {
			return errors.New("held fixture pidfd reported an invalid terminal state")
		}
		if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return nil
		}
	}
	return errors.New("held fixture process did not exit within its bound")
}

func checkpointLocalObserverCloseFixtureUnit(fixture *checkpointLocalObserverFixtureUnit) {
	if fixture != nil && fixture.pidfd >= 0 {
		_ = unix.Close(fixture.pidfd)
		fixture.pidfd = -1
	}
}

func checkpointLocalObserverShowFixtureUnit(unit string) (map[string]string, error) {
	if !strings.HasPrefix(unit, "checkpoint-local-observer-fixture-") || !strings.HasSuffix(unit, ".service") || strings.ContainsAny(unit, "/\\\x00") {
		return nil, errors.New("refusing non-fixture transient unit name")
	}
	raw, err := checkpointLocalObserverBoundedCommand(3*time.Second, "/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState", "--property=ActiveState", "--property=MainPID", "--property=ControlGroup", "--property=InvocationID", unit)
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, 5)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New("malformed bounded systemctl show result")
		}
		switch parts[0] {
		case "LoadState", "ActiveState", "MainPID", "ControlGroup", "InvocationID":
			if _, exists := values[parts[0]]; exists {
				return nil, errors.New("duplicate systemctl show property")
			}
			values[parts[0]] = parts[1]
		default:
			return nil, errors.New("unexpected systemctl show property")
		}
	}
	if values["LoadState"] == "not-found" {
		return values, nil
	}
	if len(values) != 5 {
		return nil, errors.New("incomplete systemctl show state")
	}
	return values, nil
}

func checkpointLocalObserverBoundedCommand(timeout time.Duration, executable string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	output := &checkpointLocalObserverLimitedBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	err := cmd.Run()
	if output.overflow {
		return "", errors.New("bounded system command output exceeded limit")
	}
	if ctx.Err() != nil {
		return "", fmt.Errorf("bounded system command timed out: %w", ctx.Err())
	}
	if err != nil {
		return "", fmt.Errorf("bounded system command failed: %w (%s)", err, boundedLocalObserverText(output.data))
	}
	return string(output.data), nil
}

type checkpointLocalObserverLimitedBuffer struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *checkpointLocalObserverLimitedBuffer) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...), b.overflow
}

func (b *checkpointLocalObserverLimitedBuffer) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	const limit = 4096
	remaining := limit - len(b.data)
	if remaining > 0 {
		if len(raw) > remaining {
			b.data = append(b.data, raw[:remaining]...)
		} else {
			b.data = append(b.data, raw...)
		}
	}
	if len(raw) > remaining {
		b.overflow = true
	}
	return len(raw), nil
}

func checkpointLocalObserverWaitSocket(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		info, err := os.Lstat(path)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("fixed fixture socket did not appear within its bound")
}

func checkpointLocalObserverFixtureBinding(worker *checkpointHeldLocalProcess) CheckpointManagedBinding {
	boot := checkpointLocalBootID()
	digest := func(value string) string { sum := sha256.Sum256([]byte(value)); return hex.EncodeToString(sum[:]) }
	endpoint := "http://127.0.0.1:18080"
	alias := "fixture-only"
	identity := CheckpointLocalIdentity{EvidenceKind: "controlled-source-fs-verity-v2", Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, BootID: boot, PID: worker.pid, ProcessStartTicks: worker.start, ListenerIP: "127.0.0.1", ListenerPort: 18080, ListenerSocketInode: 999, ExecutablePath: worker.exe, ExecutableSHA256: strings.ToLower(worker.exeSHA256)}
	custody := CheckpointCustodyVerification{EvidenceKind: "controlled-source-fs-verity-v2", ModelArgument: "/proc/self/fd/4", ArgvSHA256: digest("fixture-argv"), BindingSHA256: digest("fixture-custody"), Nonce: digest("fixture-nonce"), Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified", BootID: boot, PID: worker.pid, ProcessStartTicks: worker.start, ListenerSocketInode: identity.ListenerSocketInode, ActualAlias: alias}
	association := CheckpointVerifiedUnitAssociation{Custody: custody, Identity: identity, Invocation: "00000000000000000000000000000001", ControlGroup: worker.cgroup}
	return CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, CurrentIncarnation: digest(fmt.Sprintf("fixture-worker:%d:%d:%s", worker.pid, worker.start, worker.exeSHA256)), PlanSHA256: digest("fixture-plan"), CustodyBindingSHA256: custody.BindingSHA256, Alias: alias, Association: association, Placement: CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", ChildMaskUUID: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "fixture-only"}, GPUBytes: 1, HostRSSBytes: 1, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}

func writeFixtureFile(t *testing.T, path string, contents []byte, uid, gid uint32, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func boundedLocalObserverText(raw []byte) string {
	if len(raw) > 4096 {
		raw = raw[:4096]
	}
	return string(raw)
}

func checkpointLocalObserverParentFailureClassifierControls(t *testing.T) {
	t.Helper()
	const positiveSite = 245
	const source = "checkpoint_local_observer_kernel_linux_test.go:"
	header := "--- FAIL: TestCheckpointLocalObserverKernelFixture (0.00s)"
	positiveLine := fmt.Sprintf("    %s%d: controlled assertion failure", source, positiveSite)
	positive := "earlier decoy " + source + "2999: not the failure\n" + header + "\n" + positiveLine + "\n"
	cases := []struct {
		name     string
		contents string
		overflow bool
		want     string
	}{
		{name: "failed parent with earlier decoy", contents: positive, want: fmt.Sprintf("owned_test_site_%d", positiveSite)},
		{name: "wrong owner", contents: "--- FAIL: TestCheckpointLocalObserverKernelSentinel (0.00s)\n" + positiveLine + "\n", want: "unavailable"},
		{name: "malformed failure header", contents: "--- FAIL: TestCheckpointLocalObserverKernelFixture (not-duration)\n" + positiveLine + "\n", want: "unavailable"},
		{name: "missing failure header", contents: positiveLine + "\n", want: "unavailable"},
		{name: "earlier decoy only", contents: "earlier decoy " + source + "240: not a failure record\n", want: "unavailable"},
		{name: "unknown source site", contents: header + "\n    " + source + "3000: unknown assertion\n", want: "unavailable"},
		{name: "duplicate failure headers", contents: header + "\n" + header + "\n" + positiveLine + "\n", want: "unavailable"},
		{name: "duplicate source sites", contents: header + "\n" + positiveLine + "\n" + positiveLine + "\n", want: "unavailable"},
		{name: "malformed source line", contents: header + "\n    " + source + "bad: malformed assertion\n", want: "unavailable"},
		{name: "wrong source file", contents: header + "\n    another_test.go:233: not owned\n", want: "unavailable"},
		{name: "empty capture", contents: "", want: "unavailable"},
		{name: "hostile text remains private", contents: header + "\n" + fmt.Sprintf("    %s%d: private=/tmp/fixture nonce=do-not-print pid=65534\n", source, positiveSite), want: fmt.Sprintf("owned_test_site_%d", positiveSite)},
		{name: "capture overflow", overflow: true, want: "overflow"},
	}
	for _, test := range cases {
		capture := &checkpointLocalObserverParentOutputCapture{}
		if test.overflow {
			_, _ = capture.Write([]byte(strings.Repeat("x", checkpointLocalObserverParentOutputLimit+1)))
		} else {
			_, _ = capture.Write([]byte(test.contents))
		}
		if got := checkpointLocalObserverParentFailureClass(capture); got != test.want {
			t.Fatalf("parent failure classifier control %q returned %q", test.name, got)
		}
	}
	checkpointLocalObserverPollInterruptControls(t)
}

func checkpointLocalObserverPollInterrupted(err error) bool {
	return errors.Is(err, unix.EINTR)
}

func checkpointLocalObserverPollInterruptControls(t *testing.T) {
	t.Helper()
	cases := []struct {
		name      string
		err       error
		wantRetry bool
	}{
		{name: "interrupted poll", err: unix.EINTR, wantRetry: true},
		{name: "wrapped interrupted poll", err: fmt.Errorf("wrapped poll: %w", unix.EINTR), wantRetry: true},
		{name: "nil poll error"},
		{name: "would block poll", err: unix.EAGAIN},
		{name: "bad descriptor poll", err: unix.EBADF},
		{name: "unknown poll error", err: errors.New("unknown poll failure")},
	}
	for _, test := range cases {
		if got := checkpointLocalObserverPollInterrupted(test.err); got != test.wantRetry {
			t.Fatalf("poll interrupted control %q retry=%t, want %t", test.name, got, test.wantRetry)
		}
	}
}
func checkpointObserverRouteNestedAssertionSites(raw []byte) string { if len(raw) > 4096 { return "unavailable" }; const headerPrefix = "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture ("; const source = "    checkpoint_local_observer_kernel_linux_test.go:"; const continuation = "            checkpoint_local_observer_kernel_linux_test.go:"; const run = "=== RUN   TestCheckpointObserverRouteComposedKernelFixture"; headers, collecting, closed, invalid, runCount, failCount, sawAssertion, passStage, continuationCandidate, continuationRequired := 0, true, false, false, 0, 0, false, 0, false, false; sites := make([]string, 0, 4); seen := make(map[int]bool); ownedClient := ""; closeSummary := func() { collecting = false; closed = true }; for _, line := range strings.Split(string(raw), "\n") { if line == "" { if continuationCandidate { invalid = true; continuationCandidate = false }; continue }; if continuationCandidate && !strings.HasPrefix(line, continuation) { if continuationRequired { invalid = true }; continuationCandidate = false }; if strings.HasPrefix(line, "=== RUN") { runCount++; if runCount != 1 || sawAssertion || passStage != 0 || closed || line != run { invalid = true }; continue }; if line == "CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS" { if runCount != 1 || passStage != 0 || sawAssertion || closed { invalid = true }; passStage = 1; continue }; if line == "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS" { if runCount != 1 || passStage != 1 || sawAssertion || closed { invalid = true }; passStage = 2; continue }; if line == "CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS" || line == "CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY" || line == "CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS" || line == "CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2" { invalid = true; continue }; if strings.HasPrefix(line, "--- FAIL") { headers++; duration := strings.TrimSuffix(strings.TrimPrefix(line, headerPrefix), "s)"); valid := strings.HasPrefix(line, headerPrefix) && strings.HasSuffix(line, "s)") && duration != "" && strings.Count(duration, ".") <= 1 && duration[0] != '.' && duration[len(duration)-1] != '.'; for _, c := range duration { if c != '.' && (c < '0' || c > '9') { valid = false } }; if headers != 1 || !valid || closed { invalid = true }; closeSummary(); continue }; if strings.HasPrefix(line, "--- ") { invalid = true; closeSummary(); continue }; if line == "FAIL" { failCount++; if headers != 1 || failCount != 1 { invalid = true }; closeSummary(); continue }; if strings.Contains(line, "checkpoint_local_observer_kernel_linux_test.go:") { if !collecting || closed { invalid = true; continue }; record := ""; continuationLine := strings.HasPrefix(line, continuation); if continuationLine { record = strings.TrimPrefix(line, continuation) } else if strings.HasPrefix(line, source) { record = strings.TrimPrefix(line, source) } else { invalid = true; continue }; separator := strings.Index(record, ": "); if separator <= 0 || separator+2 >= len(record) { invalid = true; continue }; number, parseErr := strconv.Atoi(record[:separator]); recordText := record[separator+2:]; continuationMatch := regexp.MustCompile(`^client=(unavailable|C(?:0[1-9]|[12][0-9]|3[0-4]))$`).FindStringSubmatch(recordText); if continuationLine && (!continuationCandidate || number != 1346 || continuationMatch == nil || continuationMatch[1] != ownedClient) { invalid = true; continue }; if number == 1988 { markerMatch := regexp.MustCompile(`^REMOTE_OBSERVER_ROUTE_PID1 client=(C(?:0[1-9]|[12][0-9]|3[0-4])|unavailable) broker=(B(?:0[1-9]|[12][0-9]|3[0-8])|unavailable)(?: k=(K[1-3]))?$`).FindStringSubmatch(recordText); if continuationLine || markerMatch == nil || markerMatch[1] == "unavailable" && markerMatch[2] != "unavailable" { invalid = true; continue }; ownedClient = markerMatch[1]; continuationCandidate = true; continuationRequired = ownedClient != "unavailable" }; if parseErr != nil || number < 1 || number > 4800 || fmt.Sprintf("%d", number) != record[:separator] || seen[number] || len(sites) == 4 || number == 1346 && !continuationLine { invalid = true; continue }; seen[number] = true; sites = append(sites, record[:separator]); sawAssertion = true; if continuationLine { continuationCandidate = false; continuationRequired = false }; continue }; invalid = true }; if headers != 1 || invalid || continuationCandidate && continuationRequired || len(sites) == 0 || passStage == 1 || passStage > 0 && runCount != 1 { return "unavailable" }; return strings.Join(sites, ",") }
func checkpointObserverRouteNestedFailureDiagnostic(err error, output *checkpointLocalObserverLimitedBuffer) string { data, overflow := output.snapshot(); exit := "unavailable"; var child *exec.ExitError; if errors.As(err, &child) { if status, ok := child.Sys().(syscall.WaitStatus); ok { if status.Exited() && status.ExitStatus() > 0 && status.ExitStatus() <= 255 { exit = fmt.Sprintf("code:%d", status.ExitStatus()) } else if status.Signaled() && status.Signal() > 0 && status.Signal() <= 64 { exit = fmt.Sprintf("signal:%d", status.Signal()) } } }; overflowText := "no"; if overflow { overflowText = "yes" }; assertions := checkpointObserverRouteNestedAssertionSites(data); client, broker, phase := checkpointObserverRouteNestedStageRecords(data, overflow, assertions); return checkpointObserverRouteNestedDiagnosticRecord(exit, overflowText, assertions, client, broker, phase) }
func checkpointObserverRouteNestedFailureReducerControls() error { const header = "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\n"; const source = "    checkpoint_local_observer_kernel_linux_test.go:"; const continuation = "            checkpoint_local_observer_kernel_linux_test.go:"; const run = "=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n"; const failed = "FAIL\n"; assertion := source + "245: assertion\n"; one := assertion + header + failed; four := source + "245: a\n" + source + "246: b\n" + source + "247: c\n" + source + "248: d\n" + header; finiteMarker := source + "1988: REMOTE_OBSERVER_ROUTE_PID1 client=C14 broker=B03\n"; finite := run + finiteMarker + continuation + "1346: client=C14\n"; unavailableMarker := source + "1988: REMOTE_OBSERVER_ROUTE_PID1 client=unavailable broker=unavailable\n"; actual := finite + source + "2040: cleanup assertion\n" + header + failed; cases := []struct{name, raw, want string}{{"actual twelve-space continuation then cleanup site", actual, "1988,1346,2040"}, {"unavailable client without continuation", run + unavailableMarker + header + failed, "1988"}, {"unavailable client with continuation", run + unavailableMarker + continuation + "1346: client=unavailable\n" + header + failed, "1988,1346"}, {"actual cleanup sentinel order positive", run + "CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS\n" + assertion + header + failed, "245"}, {"legacy positive without RUN", one, "245"}, {"legacy positive with RUN", run + one, "245"}, {"four legacy sites", four, "245,246,247,248"}, {"finite continuation four-space", run + finiteMarker + source + "1346: client=C14\n" + header + failed, "unavailable"}, {"finite continuation eight-space", run + finiteMarker + "        checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\n" + header + failed, "unavailable"}, {"finite continuation blank gap", run + finiteMarker + "\n" + continuation + "1346: client=C14\n" + header + failed, "unavailable"}, {"finite continuation foreign gap", run + finiteMarker + "foreign\n" + continuation + "1346: client=C14\n" + header + failed, "unavailable"}, {"finite continuation wrong client", run + finiteMarker + continuation + "1346: client=C15\n" + header + failed, "unavailable"}, {"unavailable continuation wrong client", run + unavailableMarker + continuation + "1346: client=C14\n" + header + failed, "unavailable"}, {"unavailable client forged broker", run + source + "1988: REMOTE_OBSERVER_ROUTE_PID1 client=unavailable broker=B03\n" + header + failed, "unavailable"}, {"stray twelve-space continuation", run + continuation + "1346: client=C14\n" + assertion + header + failed, "unavailable"}, {"summary closes permanently", one + assertion, "unavailable"}, {"summary then assertion", header + failed + assertion, "unavailable"}, {"duplicate site", assertion + source + "245: duplicate\n" + header, "unavailable"}, {"excess sites", four[:len(four)-len(header)] + source + "249: excess\n" + header, "unavailable"}, {"leading zero", source + "0245: invalid\n" + header, "unavailable"}, {"signed line", source + "+245: invalid\n" + header, "unavailable"}, {"out of range", source + "4801: invalid\n" + header, "unavailable"}, {"forged path", "    /tmp/checkpoint_local_observer_kernel_linux_test.go:245: forged\n" + header, "unavailable"}, {"stack only", "\t/path/checkpoint_local_observer_kernel_linux_test.go:245 +0x20\n" + header, "unavailable"}, {"headerless", assertion, "unavailable"}, {"no assertion", header, "unavailable"}, {"incomplete", source + "245\n" + header, "unavailable"}, {"wrong run", "=== RUN   OtherTest\n" + one, "unavailable"}, {"RUN after assertion", assertion + run + header, "unavailable"}, {"duplicate run", run + run + one, "unavailable"}, {"duplicate header after cap", four + header + source + "249: after header\n", "unavailable"}, {"malformed header after cap", four + "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (bad)\n", "unavailable"}, {"different header after cap", four + "--- FAIL: OtherTest (0.00s)\n", "unavailable"}, {"cleanup sentinels reversed", run + "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\n" + assertion + header + failed, "unavailable"}, {"duplicate cleanup sentinel", run + "CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\n" + assertion + header + failed, "unavailable"}, {"impossible composed success sentinel", run + "CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY\n" + assertion + header + failed, "unavailable"}, {"impossible outside sentinel", run + "CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS\n" + assertion + header + failed, "unavailable"}, {"overflow", strings.Repeat("x", 4097), "unavailable"}}; for _, test := range cases { if got := checkpointObserverRouteNestedAssertionSites([]byte(test.raw)); got != test.want { return fmt.Errorf("nested reducer control %s", test.name) } }; return nil }
// The source-only verifier checks this finite set against the assertion call sites in this tagged fixture file.
func checkpointLocalObserverParentFailureSite(lineNumber int) string {
	switch lineNumber {
	case 245, 2107, 2111, 2115, 2121, 2125, 2129, 2150, 2195, 2200, 2205, 2209, 2214, 2219, 2234, 2241, 2244, 2247, 2251, 2254, 2257, 2260, 2267, 2273, 2279, 2283, 2294, 2301, 2305, 2308, 2315, 2318, 2322, 2325, 2332, 2336, 2339, 2348, 2351, 2355, 2359, 2363, 2367, 2371, 2377, 2382, 2387, 2391, 2425, 2428, 2436, 2440, 2444, 2451, 2458, 2463, 2469, 2474, 2479, 2484, 2495, 2505, 2509, 2513, 2517, 2521, 2525, 2529, 2533, 2539, 2545, 2549, 2553, 2558, 2563, 2570, 2575, 2580, 2584, 2588, 2593, 2597, 2602, 2611, 2621, 2626, 2630, 2633, 2776, 2779, 2783, 2787, 2791, 2796, 2801, 2806, 2816, 2821, 2827, 2833, 2842, 2851, 2862, 2882, 2889, 2895, 2908, 2918, 2926, 2934, 2942, 2949, 2966, 2973, 2981, 2986, 2992, 2996, 2999, 3131, 3136, 3140, 3144, 3151, 3155, 3160, 3164, 3168, 3171, 3180, 3189, 3194, 3198, 3203, 3210, 3214, 3218, 3222, 3227, 3233, 3237, 3247, 3251, 3257, 3275, 3286, 3293, 3299, 3305, 3311, 3314, 3322, 3328, 3333, 3337, 3344, 3353, 3357, 3362, 3366, 3370, 3373, 3378, 3382, 3388, 3392, 3397, 3401, 3404, 3408, 3411, 3419, 3429, 3436, 3441, 3447, 3450, 3456, 3461, 3466, 3469, 3474, 3477, 3480, 3484, 3488, 3491, 3496, 3500, 3504, 3513, 3516, 3520, 3796, 3805, 3812, 3819, 3827, 3833, 3837, 3842, 3845, 3854, 3862, 3869, 3876, 3883, 3890, 3900, 3904, 3908, 3911, 3958, 3962, 3966, 3971, 3974, 3978, 4026, 4240, 4257, 4260, 4263, 4274, 4278, 4283, 4287, 4291, 4295, 4298, 4302, 4305, 4706, 4709, 4712, 4758, 4784:
		return fmt.Sprintf("owned_test_site_%d", lineNumber)
	default:
		return ""
	}
}
