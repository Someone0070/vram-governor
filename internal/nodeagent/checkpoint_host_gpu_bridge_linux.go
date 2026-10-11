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
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"vram-governor/internal/checkpointgpuobserver"
)

type checkpointNodeObserverTrust struct {
	Version         int    `json:"version"`
	SocketPath      string `json:"socket_path"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

func checkpointHostGPUBridgeProductionConfig() checkpointHostGPUBridgeRuntimeConfig {
	return checkpointHostGPUBridgeRuntimeConfig{
		socketPath: checkpointHostObserverSocket, trustPath: checkpointNodeTrustPath, publicKeyPath: checkpointNodePublicKeyPath,
		discoverDevices: discoverCheckpointNvidiaDevices,
	}
}

type checkpointNodeTrustPin struct {
	file     *os.File
	path     string
	device   uint64
	inode    uint64
	size     int64
	mode     os.FileMode
	uid, gid uint32
	links    uint64
	mtime    syscall.Timespec
	ctime    syscall.Timespec
	bytes    []byte
	parents  []checkpointNodeTrustDirectory
}

type checkpointNodeTrustDirectory struct {
	path          string
	device, inode uint64
	mode          os.FileMode
	uid, gid      uint32
	links         uint64
	mtime, ctime  syscall.Timespec
	fd            int
}

func (pin *checkpointNodeTrustPin) close() {
	if pin != nil && pin.file != nil {
		_ = pin.file.Close()
		pin.file = nil
	}
	if pin != nil {
		for index := range pin.parents {
			if pin.parents[index].fd >= 0 {
				_ = unix.Close(pin.parents[index].fd)
				pin.parents[index].fd = -1
			}
		}
	}
}

func (pin *checkpointNodeTrustPin) recheck() error {
	if pin == nil || pin.file == nil {
		return errors.New("observer trust pin descriptor was not retained")
	}
	if _, err := pin.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	info, err := pin.file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != pin.device || stat.Ino != pin.inode || info.Size() != pin.size || info.Mode() != pin.mode || stat.Uid != pin.uid || stat.Gid != pin.gid || uint64(stat.Nlink) != pin.links || stat.Mtim != pin.mtime || stat.Ctim != pin.ctime {
		return errors.New("held observer trust inode metadata changed during IPC")
	}
	data, err := io.ReadAll(io.LimitReader(pin.file, pin.size+1))
	if err != nil || !bytes.Equal(data, pin.bytes) {
		return errors.New("held observer trust bytes changed during IPC")
	}
	finalInfo, err := pin.file.Stat()
	if err != nil {
		return errors.New("held observer trust metadata disappeared during read")
	}
	finalStat, finalOK := finalInfo.Sys().(*syscall.Stat_t)
	if !finalOK || uint64(finalStat.Dev) != pin.device || finalStat.Ino != pin.inode || finalInfo.Size() != pin.size || finalInfo.Mode() != pin.mode || finalStat.Uid != pin.uid || finalStat.Gid != pin.gid || uint64(finalStat.Nlink) != pin.links || finalStat.Mtim != pin.mtime || finalStat.Ctim != pin.ctime {
		return errors.New("held observer trust metadata changed during bounded re-read")
	}
	pathInfo, err := os.Lstat(pin.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("observer trust path was replaced during IPC")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(pathStat.Dev) != pin.device || pathStat.Ino != pin.inode || pathInfo.Size() != pin.size || pathInfo.Mode() != pin.mode || pathStat.Uid != pin.uid || pathStat.Gid != pin.gid || uint64(pathStat.Nlink) != pin.links || pathStat.Mtim != pin.mtime || pathStat.Ctim != pin.ctime {
		return errors.New("observer trust path no longer names held inode")
	}
	for _, parent := range pin.parents {
		var held unix.Stat_t
		if parent.fd < 0 || unix.Fstat(parent.fd, &held) != nil || uint64(held.Dev) != parent.device || held.Ino != parent.inode || held.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(held.Mode&07777) != parent.mode.Perm() || held.Uid != parent.uid || held.Gid != parent.gid || uint64(held.Nlink) != parent.links || !checkpointNodeTimespecEqual(held.Mtim, parent.mtime) || !checkpointNodeTimespecEqual(held.Ctim, parent.ctime) {
			return errors.New("held observer trust parent descriptor changed")
		}
		current, err := os.Lstat(parent.path)
		if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() {
			return errors.New("observer trust parent changed during IPC")
		}
		currentStat, ok := current.Sys().(*syscall.Stat_t)
		if !ok || uint64(currentStat.Dev) != parent.device || currentStat.Ino != parent.inode || current.Mode() != parent.mode || currentStat.Uid != parent.uid || currentStat.Gid != parent.gid || uint64(currentStat.Nlink) != parent.links || currentStat.Mtim != parent.mtime || currentStat.Ctim != parent.ctime {
			return errors.New("observer trust parent authority changed during IPC")
		}
	}
	return nil
}

type checkpointHeldLocalProcess struct {
	pid       int
	start     uint64
	uid       uint32
	exe       string
	exeSHA256 string
	pidfd     int
	nsfd      int
	namespace checkpointgpuobserver.Namespace
	cgroup    string
	nspid     []int
}

func (process *checkpointHeldLocalProcess) close() {
	if process == nil {
		return
	}
	if process.pidfd >= 0 {
		_ = unix.Close(process.pidfd)
		process.pidfd = -1
	}
	if process.nsfd >= 0 {
		_ = unix.Close(process.nsfd)
		process.nsfd = -1
	}
}

func observeCheckpointHostGPUAttributionPlatformForRole(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, expectedRole string) (checkpointHostGPUObservation, error) {
	return observeCheckpointHostGPUAttributionPlatformForRoleUsing(ctx, workerPID, expectedStart, plan, placement, expectedRole, checkpointHostGPUBridgeProductionConfig())
}

func observeCheckpointHostGPUAttributionLocalObserverUsing(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, config checkpointHostGPUBridgeRuntimeConfig) (checkpointHostGPUObservation, error) {
	if os.Geteuid() != 0 {
		return checkpointHostGPUObservation{}, errors.New("local-observer host bridge requires the fixed root collector")
	}
	return observeCheckpointHostGPUAttributionPlatformForRoleUsing(ctx, workerPID, expectedStart, plan, placement, "local-observer", config)
}

func observeCheckpointHostGPUAttributionPlatformForRoleUsing(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, expectedRole string, config checkpointHostGPUBridgeRuntimeConfig) (checkpointHostGPUObservation, error) {
	if ctx == nil || workerPID <= 1 || expectedStart == 0 || plan.Placement == nil || plan.Placement.MaxAccelerators != 1 || !checkpointGPUUUIDRE.MatchString(placement.ChildMaskUUID) {
		return checkpointHostGPUObservation{}, errors.New("nested host GPU attribution request is invalid")
	}
	if config.socketPath == "" || config.trustPath == "" || config.publicKeyPath == "" || config.discoverDevices == nil {
		return checkpointHostGPUObservation{}, errors.New("host observer private runtime pins are incomplete")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointHostGPUBridgeTimeout)
	defer cancel()
	worker, err := openCheckpointHeldLocalProcess(workerPID)
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	defer worker.close()
	if worker.start != expectedStart {
		return checkpointHostGPUObservation{}, errors.New("nested worker incarnation changed before host attribution")
	}
	if err := requireNestedCheckpointPIDNamespace(worker.namespace); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	self, err := openCheckpointHeldLocalProcess(os.Getpid())
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	defer self.close()
	if self.namespace != worker.namespace {
		return checkpointHostGPUObservation{}, errors.New("nested host GPU bridge caller is outside the worker PID namespace")
	}
	init, err := findCheckpointLocalNamespaceInit(worker.namespace)
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	defer init.close()
	if init.nspid[len(init.nspid)-1] != 1 || init.namespace != worker.namespace || init.pid == 0 {
		return checkpointHostGPUObservation{}, errors.New("nested PID namespace init is not uniquely joined to the worker")
	}
	workerLocalPID := worker.nspid[len(worker.nspid)-1]
	if workerLocalPID <= 1 {
		return checkpointHostGPUObservation{}, errors.New("nested worker has no valid namespace-relative PID")
	}
	devices, err := config.discoverDevices(bounded)
	if err != nil {
		return checkpointHostGPUObservation{}, fmt.Errorf("resolve pinned GPU UUID to PCI identity: %w", err)
	}
	var pci string
	for _, device := range devices {
		if device.UUID == placement.ChildMaskUUID {
			if pci != "" {
				return checkpointHostGPUObservation{}, errors.New("pinned GPU UUID is duplicated in local fresh inventory")
			}
			pci = device.PCI
		}
	}
	if pci == "" {
		return checkpointHostGPUObservation{}, errors.New("pinned GPU UUID is absent from local fresh inventory")
	}
	if plan.Placement.IdentityKind == "pci_bus_id" && !strings.EqualFold(pci, plan.Placement.PhysicalIdentity) {
		return checkpointHostGPUObservation{}, errors.New("fresh local PCI identity differs from the pinned physical plan")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	request := checkpointgpuobserver.Request{
		Version: checkpointgpuobserver.ProtocolVersion, Nonce: hex.EncodeToString(nonce),
		InitPID: 1, InitStartTicks: init.start,
		InitNamespaceDev: init.namespace.Device, InitNamespaceInode: init.namespace.Inode,
		InitNamespaceFS: init.namespace.Filesystem, InitNamespaceType: init.namespace.NamespaceType,
		WorkerPID: workerLocalPID, WorkerStartTicks: worker.start,
		WorkerNamespaceDev: worker.namespace.Device, WorkerNamespaceInode: worker.namespace.Inode,
		WorkerNamespaceFS: worker.namespace.Filesystem, WorkerNamespaceType: worker.namespace.NamespaceType,
		GPUUUID: placement.ChildMaskUUID, GPUPCI: pci,
	}
	requestBytes, err := checkpointgpuobserver.MarshalRequest(request)
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	trust, publicKey, trustPins, err := loadCheckpointNodeObserverTrustAt(config.trustPath, config.publicKeyPath, config.socketPath)
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	defer func() {
		for _, pin := range trustPins {
			pin.close()
		}
	}()
	if trust.SocketPath != config.socketPath {
		return checkpointHostGPUObservation{}, errors.New("node observer trust names a non-fixed socket")
	}
	connection, err := (&net.Dialer{Timeout: 1200 * time.Millisecond}).DialContext(bounded, "unix", trust.SocketPath)
	if err != nil {
		return checkpointHostGPUObservation{}, fmt.Errorf("fixed host GPU observer is unavailable: %w", err)
	}
	defer connection.Close()
	deadline := time.Now().Add(3 * time.Second)
	if parentDeadline, ok := bounded.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	_ = connection.SetDeadline(deadline)
	if err := checkpointWriteFrame(connection, requestBytes); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	responseBytes, err := checkpointReadFrame(connection, checkpointgpuobserver.MaxResponseBytes)
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	response, err := verifyCheckpointHostGPUResponseForRole(responseBytes, publicKey, request, expectedRole, time.Now().UTC().UnixNano())
	if err != nil {
		return checkpointHostGPUObservation{}, err
	}
	for _, pin := range trustPins {
		if err := pin.recheck(); err != nil {
			return checkpointHostGPUObservation{}, err
		}
	}
	if err := validateCheckpointObserverLocalPeerJoin(response, self, os.Getpid(), checkpointLocalBootID()); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	if err := recheckCheckpointHeldLocalProcess(self); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	if err := recheckCheckpointHeldLocalProcess(worker); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	if err := recheckCheckpointHeldLocalProcess(init); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	if err := requireNestedCheckpointPIDNamespace(worker.namespace); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	observation := checkpointHostGPUObservation{Bytes: response.GPU.Bytes, Response: response}
	if err := validateCheckpointHostGPUObservation(observation, placement, plan); err != nil {
		return checkpointHostGPUObservation{}, err
	}
	for _, pin := range trustPins {
		if err := pin.recheck(); err != nil {
			return checkpointHostGPUObservation{}, err
		}
	}
	return observation, nil
}

func verifyCheckpointHostGPUResponseForRole(raw []byte, publicKey ed25519.PublicKey, request checkpointgpuobserver.Request, expectedRole string, nowUnixNS int64) (checkpointgpuobserver.Response, error) {
	response, err := checkpointgpuobserver.VerifyResponse(raw, publicKey, request, nowUnixNS)
	if err != nil {
		return checkpointgpuobserver.Response{}, err
	}
	if err := validateCheckpointHostGPUResponseRole(response.Role, expectedRole); err != nil {
		return checkpointgpuobserver.Response{}, err
	}
	return response, nil
}

func validateCheckpointObserverLocalPeerJoin(response checkpointgpuobserver.Response, self *checkpointHeldLocalProcess, currentPID int, currentBootID string) error {
	if self == nil || len(response.Peer.NSpid) == 0 || response.BootID != currentBootID || response.Peer.Namespace != self.namespace || response.Peer.NSpid[len(response.Peer.NSpid)-1] != currentPID || response.Peer.StartTicks != self.start || response.PeerUID != self.uid || response.PeerExecutablePath != self.exe || !strings.EqualFold(response.PeerExecutableSHA256, self.exeSHA256) {
		return errors.New("signed host peer does not join this current local process and boot")
	}
	return nil
}

func checkpointLocalBootID() string {
	raw, err := checkpointReadBounded("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func openCheckpointHeldLocalProcess(pid int) (*checkpointHeldLocalProcess, error) {
	if pid <= 0 {
		return nil, errors.New("local managed process id is invalid")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	process := &checkpointHeldLocalProcess{pid: pid, pidfd: pidfd, nsfd: -1}
	failed := func(err error) (*checkpointHeldLocalProcess, error) { process.close(); return nil, err }
	procDir := filepath.Join("/proc", strconv.Itoa(pid))
	nsfd, err := unix.Open(filepath.Join(procDir, "ns/pid"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed(err)
	}
	process.nsfd = nsfd
	namespace, err := checkpointLocalNamespaceFromFD(nsfd)
	if err != nil {
		return failed(err)
	}
	start, err := checkpointProcessStart(procDir, pid)
	if err != nil {
		return failed(err)
	}
	nspid, err := checkpointReadNSpid(procDir, pid)
	if err != nil {
		return failed(err)
	}
	cgroup, err := checkpointReadLocalCgroup(procDir)
	if err != nil {
		return failed(err)
	}
	process.namespace, process.start, process.nspid, process.cgroup = namespace, start, nspid, cgroup
	var owner unix.Stat_t
	if err := unix.Stat(procDir, &owner); err != nil {
		return failed(err)
	}
	process.uid = owner.Uid
	process.exe, process.exeSHA256, err = checkpointLocalExecutableIdentity(procDir)
	if err != nil {
		return failed(err)
	}
	if err := checkpointLocalPIDFDAlive(pidfd); err != nil {
		return failed(err)
	}
	return process, nil
}

func checkpointWorkerUsesNestedPIDNamespace(ctx context.Context, pid int) (bool, error) {
	if ctx == nil || pid <= 1 {
		return false, errors.New("namespace route request is invalid")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	worker, err := openCheckpointHeldLocalProcess(pid)
	if err != nil {
		return false, err
	}
	defer worker.close()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if worker.namespace.Filesystem != checkpointNSFSMagic || worker.namespace.NamespaceType != uint64(unix.CLONE_NEWPID) {
		return false, errors.New("managed worker PID namespace descriptor is unsupported")
	}
	current, err := checkpointLocalNamespaceAt("/proc/self/ns/pid")
	if err != nil {
		return false, err
	}
	if worker.namespace.Inode == checkpointPIDNamespaceInitInode {
		if current != worker.namespace {
			return false, errors.New("initial namespace worker is outside the node observer namespace")
		}
		return false, nil
	}
	return true, nil
}

func findCheckpointLocalNamespaceInit(namespace checkpointgpuobserver.Namespace) (*checkpointHeldLocalProcess, error) {
	current, err := checkpointLocalNamespaceAt("/proc/1/ns/pid")
	if err == nil && current == namespace {
		return openCheckpointHeldLocalProcess(1)
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var candidate int
	for index, entry := range entries {
		if index >= 32768 {
			return nil, errors.New("local namespace init scan exceeded fixed process bound")
		}
		if !entry.IsDir() {
			continue
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 1 {
			continue
		}
		procDir := filepath.Join("/proc", entry.Name())
		chain, chainErr := checkpointReadNSpid(procDir, pid)
		if chainErr != nil || chain[len(chain)-1] != 1 {
			continue
		}
		observed, nsErr := checkpointLocalNamespaceAt(filepath.Join(procDir, "ns/pid"))
		if nsErr != nil || observed != namespace {
			continue
		}
		if candidate != 0 {
			return nil, errors.New("nested PID namespace init mapping is ambiguous")
		}
		candidate = pid
	}
	if candidate == 0 {
		return nil, errors.New("nested PID namespace init mapping is absent")
	}
	return openCheckpointHeldLocalProcess(candidate)
}

func requireNestedCheckpointPIDNamespace(namespace checkpointgpuobserver.Namespace) error {
	if namespace.Filesystem != checkpointNSFSMagic || namespace.NamespaceType != uint64(unix.CLONE_NEWPID) || namespace.Inode == checkpointPIDNamespaceInitInode {
		return errors.New("host bridge is selected only for an independently observed nested PID namespace")
	}
	return nil
}

func checkpointLocalNamespaceAt(path string) (checkpointgpuobserver.Namespace, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return checkpointgpuobserver.Namespace{}, err
	}
	defer unix.Close(fd)
	return checkpointLocalNamespaceFromFD(fd)
}

func checkpointLocalNamespaceFromFD(fd int) (checkpointgpuobserver.Namespace, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return checkpointgpuobserver.Namespace{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return checkpointgpuobserver.Namespace{}, err
	}
	typeValue, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || typeValue <= 0 || uint64(fs.Type) != checkpointNSFSMagic {
		return checkpointgpuobserver.Namespace{}, errors.New("local PID namespace descriptor is unsupported")
	}
	return checkpointgpuobserver.Namespace{Device: uint64(stat.Dev), Inode: stat.Ino, Filesystem: uint64(fs.Type), NamespaceType: uint64(typeValue)}, nil
}

func checkpointReadNSpid(procDir string, expectedPID int) ([]int, error) {
	raw, err := checkpointReadBounded(filepath.Join(procDir, "status"), 64<<10)
	if err != nil {
		return nil, err
	}
	var chain []int
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		if found {
			return nil, errors.New("process has duplicate NSpid chains")
		}
		found = true
		for _, field := range strings.Fields(strings.TrimPrefix(line, "NSpid:")) {
			value, err := strconv.Atoi(field)
			if err != nil || value <= 0 || len(chain) >= 32 {
				return nil, errors.New("process NSpid chain is malformed")
			}
			chain = append(chain, value)
		}
	}
	if !found || len(chain) == 0 || chain[0] != expectedPID {
		return nil, errors.New("process NSpid chain does not begin with held host-visible PID")
	}
	for index, value := range chain {
		if value == 1 && index != len(chain)-1 {
			return nil, errors.New("process NSpid chain is ambiguous")
		}
	}
	return chain, nil
}

func checkpointReadLocalCgroup(procDir string) (string, error) {
	raw, err := checkpointReadBounded(filepath.Join(procDir, "cgroup"), checkpointgpuobserver.MaxCgroupBytes)
	if err != nil {
		return "", err
	}
	var path string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			return "", errors.New("local process cgroup record is malformed")
		}
		if parts[0] == "0" && parts[1] == "" {
			if path != "" {
				return "", errors.New("local process has duplicate unified cgroups")
			}
			path = parts[2]
		}
	}
	if path == "" || len(path) > checkpointgpuobserver.MaxCgroupBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "..") {
		return "", errors.New("local process cgroup is absent or unsafe")
	}
	return path, nil
}

func recheckCheckpointHeldLocalProcess(held *checkpointHeldLocalProcess) error {
	if held == nil || held.pidfd < 0 || held.nsfd < 0 {
		return errors.New("held local process identity is incomplete")
	}
	if err := checkpointLocalPIDFDAlive(held.pidfd); err != nil {
		return err
	}
	current, err := openCheckpointHeldLocalProcess(held.pid)
	if err != nil {
		return err
	}
	defer current.close()
	if current.start != held.start || current.namespace != held.namespace || current.cgroup != held.cgroup || current.uid != held.uid || current.exe != held.exe || !strings.EqualFold(current.exeSHA256, held.exeSHA256) || !sameCheckpointIntSlice(current.nspid, held.nspid) {
		return errors.New("local process incarnation, namespace, or cgroup changed during host attribution")
	}
	return nil
}

func checkpointLocalExecutableIdentity(procDir string) (string, string, error) {
	path, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil || path == "" || strings.HasSuffix(path, " (deleted)") {
		return "", "", errors.New("local caller executable path is unavailable or deleted")
	}
	fd, err := unix.Open(filepath.Join(procDir, "exe"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", "", err
	}
	file := os.NewFile(uintptr(fd), "local-held-executable")
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 256<<20 {
		return "", "", errors.New("local caller executable is outside fixed bounds")
	}
	data, err := io.ReadAll(io.LimitReader(file, (256<<20)+1))
	if err != nil || int64(len(data)) != before.Size() {
		return "", "", errors.New("local caller executable changed or exceeded bounds")
	}
	after, err := file.Stat()
	if err != nil || !sameCheckpointObserverExecutableStat(before, after) {
		return "", "", errors.New("local caller executable metadata changed during read")
	}
	digest := sha256.Sum256(data)
	return filepath.Clean(path), hex.EncodeToString(digest[:]), nil
}

func sameCheckpointObserverExecutableStat(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func checkpointLocalPIDFDAlive(fd int) error {
	var poll [1]unix.PollFd
	poll[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	ready, err := unix.Poll(poll[:], 0)
	if err != nil {
		return err
	}
	if ready != 0 || poll[0].Revents != 0 {
		return errors.New("held local process exited during attribution")
	}
	return nil
}

func sameCheckpointIntSlice(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func loadCheckpointNodeObserverTrust() (checkpointNodeObserverTrust, ed25519.PublicKey, []*checkpointNodeTrustPin, error) {
	return loadCheckpointNodeObserverTrustAt(checkpointNodeTrustPath, checkpointNodePublicKeyPath, checkpointHostObserverSocket)
}

func loadCheckpointNodeObserverTrustAt(trustPath, publicKeyPath, expectedSocket string) (checkpointNodeObserverTrust, ed25519.PublicKey, []*checkpointNodeTrustPin, error) {
	var trust checkpointNodeObserverTrust
	trustPin, err := openRootOnlyNodeFile(trustPath, 16<<10)
	if err != nil {
		return trust, nil, nil, err
	}
	pins := []*checkpointNodeTrustPin{trustPin}
	fail := func(err error) (checkpointNodeObserverTrust, ed25519.PublicKey, []*checkpointNodeTrustPin, error) {
		for _, pin := range pins {
			pin.close()
		}
		return trust, nil, nil, err
	}
	raw := trustPin.bytes
	if checkpointRejectDuplicateJSON(raw) != nil {
		return fail(errors.New("node observer trust file is malformed"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&trust); err != nil {
		return fail(errors.New("node observer trust fields are invalid"))
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fail(errors.New("node observer trust contains trailing data"))
	}
	canonical, err := json.Marshal(trust)
	if err != nil || !bytes.Equal(raw, canonical) || trust.Version != checkpointgpuobserver.ProtocolVersion || trust.SocketPath != expectedSocket || len(trust.PublicKeySHA256) != 64 {
		return fail(errors.New("node observer trust is noncanonical or not pinned to fixed policy"))
	}
	for _, value := range trust.PublicKeySHA256 {
		if value < '0' || value > '9' && (value < 'a' || value > 'f') {
			return fail(errors.New("node observer public key pin is malformed"))
		}
	}
	keyPin, err := openRootOnlyNodeFile(publicKeyPath, ed25519.PublicKeySize)
	if err != nil {
		return fail(errors.New("root-owned observer public key is absent or unsafe"))
	}
	pins = append(pins, keyPin)
	key := keyPin.bytes
	if len(key) != ed25519.PublicKeySize {
		return fail(errors.New("root-owned observer public key is absent or unsafe"))
	}
	digest := sha256.Sum256(key)
	if hex.EncodeToString(digest[:]) != trust.PublicKeySHA256 {
		return fail(errors.New("observer public key does not match root-approved fingerprint"))
	}
	return trust, ed25519.PublicKey(key), pins, nil
}

func openRootOnlyNodeFile(path string, maximum int64) (*checkpointNodeTrustPin, error) {
	parents, err := holdCheckpointRootTrustDirectories(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		for _, parent := range parents {
			_ = unix.Close(parent.fd)
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "root-only-observer-pin")
	if file == nil {
		_ = unix.Close(fd)
		for _, parent := range parents {
			_ = unix.Close(parent.fd)
		}
		return nil, errors.New("observer pin descriptor is unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0022 != 0 {
		_ = file.Close()
		for _, parent := range parents {
			_ = unix.Close(parent.fd)
		}
		return nil, errors.New("observer pin file has unsafe type, mode, or size")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		_ = file.Close()
		for _, parent := range parents {
			_ = unix.Close(parent.fd)
		}
		return nil, errors.New("observer pin is not root-owned and singly linked")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != info.Size() {
		_ = file.Close()
		for _, parent := range parents {
			_ = unix.Close(parent.fd)
		}
		return nil, errors.New("observer pin changed during bounded read")
	}
	pin := &checkpointNodeTrustPin{file: file, path: path, device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink), mtime: stat.Mtim, ctime: stat.Ctim, bytes: data, parents: parents}
	if err := pin.recheck(); err != nil {
		pin.close()
		return nil, err
	}
	return pin, nil
}

func holdCheckpointRootTrustDirectories(path string) ([]checkpointNodeTrustDirectory, error) {
	var parents []checkpointNodeTrustDirectory
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			closeCheckpointNodeTrustDirectories(parents)
			return nil, errors.New("root-owned observer trust directory is missing or linked")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			closeCheckpointNodeTrustDirectories(parents)
			return nil, errors.New("observer trust directory is not protected root authority")
		}
		fd, openErr := unix.Open(current, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			closeCheckpointNodeTrustDirectories(parents)
			return nil, errors.New("observer trust parent descriptor could not be held")
		}
		var held unix.Stat_t
		if unix.Fstat(fd, &held) != nil || uint64(held.Dev) != uint64(stat.Dev) || held.Ino != stat.Ino || held.Uid != stat.Uid || held.Gid != stat.Gid || held.Nlink != stat.Nlink || !checkpointNodeTimespecEqual(held.Mtim, stat.Mtim) || !checkpointNodeTimespecEqual(held.Ctim, stat.Ctim) {
			_ = unix.Close(fd)
			closeCheckpointNodeTrustDirectories(parents)
			return nil, errors.New("observer trust parent changed while opening descriptor")
		}
		parents = append(parents, checkpointNodeTrustDirectory{path: current, device: uint64(stat.Dev), inode: stat.Ino, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink), mtime: stat.Mtim, ctime: stat.Ctim, fd: fd})
		if filepath.Dir(current) == current {
			break
		}
	}
	return parents, nil
}

func checkpointNodeTimespecEqual(a unix.Timespec, b syscall.Timespec) bool {
	return a.Sec == b.Sec && a.Nsec == b.Nsec
}

func closeCheckpointNodeTrustDirectories(parents []checkpointNodeTrustDirectory) {
	for _, parent := range parents {
		if parent.fd >= 0 {
			_ = unix.Close(parent.fd)
		}
	}
}

func checkpointRejectDuplicateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			if token == nil {
				return errors.New("null not allowed")
			}
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return errors.New("duplicate key")
				}
				seen[key] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("invalid object")
			}
			return nil
		}
		if delim == '[' {
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("invalid array")
			}
			return nil
		}
		return errors.New("unexpected JSON container")
	}
	if err := walk(); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func checkpointWriteFrame(connection net.Conn, raw []byte) error {
	if len(raw) == 0 || len(raw) > checkpointgpuobserver.MaxRequestBytes {
		return errors.New("observer request frame is outside bounds")
	}
	header := []byte{byte(uint32(len(raw)) >> 24), byte(uint32(len(raw)) >> 16), byte(uint32(len(raw)) >> 8), byte(len(raw))}
	if err := writeCheckpointFull(connection, header); err != nil {
		return err
	}
	return writeCheckpointFull(connection, raw)
}

func writeCheckpointFull(writer io.Writer, raw []byte) error {
	for len(raw) > 0 {
		written, err := writer.Write(raw)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}

func checkpointReadFrame(connection net.Conn, maximum int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return nil, err
	}
	length := int(uint32(header[0])<<24 | uint32(header[1])<<16 | uint32(header[2])<<8 | uint32(header[3]))
	if length <= 0 || length > maximum {
		return nil, errors.New("observer response frame is outside bounds")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(connection, body); err != nil {
		return nil, err
	}
	return body, nil
}
