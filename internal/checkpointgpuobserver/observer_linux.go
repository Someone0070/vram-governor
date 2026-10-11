//go:build linux

package checkpointgpuobserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	ObserverConfigPath = "/etc/vram-governor/checkpoint-gpu-observer.json"
	ObserverKeyPath    = "/etc/vram-governor/checkpoint-gpu-observer.key"
	observerProcRoot   = "/proc"
	observerSMIPath    = "/usr/bin/nvidia-smi"
	observerFrameMax   = MaxRequestBytes
	observerScanLimit  = 32768
	observerScanTime   = 3 * time.Second
	observerReplyTTL   = 2 * time.Second
	observerProbeTime  = 3 * time.Second
	observerCommandMax = 256 << 10
	observerNSFSMagic  = 0x6e736673
	observerInitPIDNS  = 0xeffffffc
)

type PeerAuthority struct {
	Role             string   `json:"role"`
	UID              uint32   `json:"uid"`
	ExecutablePath   string   `json:"executable_path"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	CgroupRoots      []string `json:"cgroup_roots"`
}

type ContainerAuthority struct {
	CgroupRoot                string `json:"cgroup_root"`
	NodeAgentUID              uint32 `json:"node_agent_uid"`
	NodeAgentExecutablePath   string `json:"node_agent_executable_path"`
	NodeAgentExecutableSHA256 string `json:"node_agent_executable_sha256"`
}

type ObserverConfig struct {
	Version         int                  `json:"version"`
	SocketGID       uint32               `json:"socket_gid"`
	PeerAuthorities []PeerAuthority      `json:"peer_authorities"`
	Containers      []ContainerAuthority `json:"containers"`
}

func peerAuthorityByRole(authorities []PeerAuthority, role string) (PeerAuthority, bool) {
	for _, authority := range authorities {
		if authority.Role == role {
			return authority, true
		}
	}
	return PeerAuthority{}, false
}

func peerAuthoritiesOverlap(left, right PeerAuthority) bool {
	if left.UID != right.UID || left.ExecutablePath != right.ExecutablePath || !strings.EqualFold(left.ExecutableSHA256, right.ExecutableSHA256) {
		return false
	}
	for _, leftRoot := range left.CgroupRoots {
		for _, rightRoot := range right.CgroupRoots {
			if sameCgroupRoot(leftRoot, rightRoot) || sameCgroupRoot(rightRoot, leftRoot) {
				return true
			}
		}
	}
	return false
}

type heldProcess struct {
	value     Process
	pidfd     int
	nsfd      int
	exe       string
	uid       uint32
	exeSHA256 string
}

type observerPinnedDirectory struct {
	path          string
	fd            int
	device, inode uint64
	mode          os.FileMode
	uid, gid      uint32
	links         uint64
	mtime, ctime  syscall.Timespec
}
type observerPinnedAuthorityFile struct {
	mu      sync.Mutex
	file    *os.File
	path    string
	info    os.FileInfo
	bytes   []byte
	parents []observerPinnedDirectory
}

func openRootPinnedAuthorityFile(path string, maximum int64) (*observerPinnedAuthorityFile, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root-pinned observer file requires root")
	}
	parents, err := holdObserverRootDirectories(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		closeObserverRootDirectories(parents)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "root-pinned-observer-authority")
	if file == nil {
		_ = unix.Close(fd)
		closeObserverRootDirectories(parents)
		return nil, errors.New("root observer file descriptor unavailable")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > maximum {
		_ = file.Close()
		closeObserverRootDirectories(parents)
		return nil, errors.New("root observer file type, mode, or size is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 {
		_ = file.Close()
		closeObserverRootDirectories(parents)
		return nil, errors.New("root observer file owner or link count is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		_ = file.Close()
		closeObserverRootDirectories(parents)
		return nil, errors.New("root observer file changed or exceeded bounded read")
	}
	pin := &observerPinnedAuthorityFile{file: file, path: path, info: info, bytes: raw, parents: parents}
	if err := pin.recheck(); err != nil {
		pin.close()
		return nil, err
	}
	return pin, nil
}

func holdObserverRootDirectories(path string) ([]observerPinnedDirectory, error) {
	var result []observerPinnedDirectory
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			closeObserverRootDirectories(result)
			return nil, errors.New("root observer authority parent is missing or linked")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			closeObserverRootDirectories(result)
			return nil, errors.New("root observer authority parent is not protected")
		}
		fd, err := unix.Open(current, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
		if err != nil {
			closeObserverRootDirectories(result)
			return nil, err
		}
		var held unix.Stat_t
		if unix.Fstat(fd, &held) != nil || held.Dev != stat.Dev || held.Ino != stat.Ino || held.Uid != stat.Uid || held.Gid != stat.Gid || held.Nlink != stat.Nlink || !sameObserverTimespec(held.Mtim, stat.Mtim) || !sameObserverTimespec(held.Ctim, stat.Ctim) {
			_ = unix.Close(fd)
			closeObserverRootDirectories(result)
			return nil, errors.New("root observer parent changed while opening")
		}
		result = append(result, observerPinnedDirectory{path: current, fd: fd, device: uint64(stat.Dev), inode: stat.Ino, mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink), mtime: stat.Mtim, ctime: stat.Ctim})
		if filepath.Dir(current) == current {
			break
		}
	}
	return result, nil
}
func closeObserverRootDirectories(parents []observerPinnedDirectory) {
	for _, parent := range parents {
		if parent.fd >= 0 {
			_ = unix.Close(parent.fd)
		}
	}
}

func (pin *observerPinnedAuthorityFile) close() {
	if pin == nil {
		return
	}
	if pin.file != nil {
		_ = pin.file.Close()
		pin.file = nil
	}
	for index := range pin.parents {
		if pin.parents[index].fd >= 0 {
			_ = unix.Close(pin.parents[index].fd)
			pin.parents[index].fd = -1
		}
	}
}
func (pin *observerPinnedAuthorityFile) recheck() error {
	if pin == nil {
		return errors.New("held root observer authority descriptor is unavailable")
	}
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin == nil || pin.file == nil {
		return errors.New("held root observer authority descriptor is unavailable")
	}
	before, err := pin.file.Stat()
	if err != nil || !samePinnedStat(pin.info, before) {
		return errors.New("held root observer authority metadata changed")
	}
	if _, err := pin.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(pin.file, int64(len(pin.bytes))+1))
	if err != nil || !bytes.Equal(raw, pin.bytes) {
		return errors.New("held root observer authority bytes changed")
	}
	after, err := pin.file.Stat()
	if err != nil || !samePinnedStat(pin.info, after) {
		return errors.New("held root observer authority changed while rechecking")
	}
	pathInfo, err := os.Lstat(pin.path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("root observer authority path changed")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	expected := pin.info.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Dev != expected.Dev || pathStat.Ino != expected.Ino || !samePinnedStat(pin.info, pathInfo) {
		return errors.New("root observer authority path no longer names held inode")
	}
	for _, parent := range pin.parents {
		var held unix.Stat_t
		if parent.fd < 0 || unix.Fstat(parent.fd, &held) != nil || uint64(held.Dev) != parent.device || held.Ino != parent.inode || held.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(held.Mode&07777) != parent.mode.Perm() || held.Uid != parent.uid || held.Gid != parent.gid || uint64(held.Nlink) != parent.links || !sameObserverTimespec(held.Mtim, parent.mtime) || !sameObserverTimespec(held.Ctim, parent.ctime) {
			return errors.New("held root observer authority parent changed")
		}
		current, e := os.Lstat(parent.path)
		if e != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() {
			return errors.New("root observer authority parent path changed")
		}
		st, ok := current.Sys().(*syscall.Stat_t)
		if !ok || uint64(st.Dev) != parent.device || st.Ino != parent.inode || current.Mode() != parent.mode || st.Uid != parent.uid || st.Gid != parent.gid || uint64(st.Nlink) != parent.links || st.Mtim != parent.mtime || st.Ctim != parent.ctime {
			return errors.New("root observer authority parent no longer matches held directory")
		}
	}
	return nil
}

func sameObserverTimespec(a unix.Timespec, b syscall.Timespec) bool {
	return a.Sec == b.Sec && a.Nsec == b.Nsec
}

func (p *heldProcess) close() {
	if p == nil {
		return
	}
	if p.pidfd >= 0 {
		_ = unix.Close(p.pidfd)
		p.pidfd = -1
	}
	if p.nsfd >= 0 {
		_ = unix.Close(p.nsfd)
		p.nsfd = -1
	}
}

// Serve runs the fixed host-local observer. Paths, command, environment,
// protocol, and socket framing are compile-time policy; the root-owned config
// only supplies narrow peer and container authority.
func Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("observer service context is required")
	}
	configPin, err := openRootPinnedAuthorityFile(ObserverConfigPath, 64<<10)
	if err != nil {
		return fmt.Errorf("load fixed host observer policy: %w", err)
	}
	defer configPin.close()
	config, err := decodeObserverConfig(configPin.bytes)
	if err != nil {
		return fmt.Errorf("load fixed host observer policy: %w", err)
	}
	keyPin, err := openRootPinnedAuthorityFile(ObserverKeyPath, ed25519.PrivateKeySize)
	if err != nil || keyPin == nil {
		return errors.New("root-owned observer signing key is absent or unsafe")
	}
	if len(keyPin.bytes) != ed25519.PrivateKeySize {
		keyPin.close()
		return errors.New("root-owned observer signing key is absent or unsafe")
	}
	defer keyPin.close()
	key := ed25519.PrivateKey(keyPin.bytes)
	if err := configPin.recheck(); err != nil {
		return err
	}
	if err := keyPin.recheck(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("host observer must run as root")
	}
	if err := ensureInitialPIDNamespace(); err != nil {
		return err
	}
	if err := verifyFixedSocketDirectory(filepath.Dir(ObserverSocketPath)); err != nil {
		return err
	}
	listener, err := net.Listen("unix", ObserverSocketPath)
	if err != nil {
		return fmt.Errorf("listen on fixed observer socket: %w", err)
	}
	defer listener.Close()
	socketInfo, err := os.Lstat(ObserverSocketPath)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		return errors.New("fixed observer socket path is not a Unix socket")
	}
	socketStat, ok := socketInfo.Sys().(*syscall.Stat_t)
	if !ok || socketStat.Uid != 0 {
		return errors.New("fixed observer socket is not root-owned")
	}
	if err := os.Chmod(ObserverSocketPath, 0660); err != nil {
		return err
	}
	if err := os.Chown(ObserverSocketPath, 0, int(config.SocketGID)); err != nil {
		return err
	}
	defer func() {
		current, statErr := os.Lstat(ObserverSocketPath)
		if statErr != nil {
			return
		}
		currentStat, currentOK := current.Sys().(*syscall.Stat_t)
		if currentOK && current.Mode()&os.ModeSocket != 0 && currentStat.Dev == socketStat.Dev && currentStat.Ino == socketStat.Ino {
			_ = os.Remove(ObserverSocketPath)
		}
	}()
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		return errors.New("fixed observer listener is not Unix")
	}
	unixListener.SetUnlinkOnClose(false)
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 32)
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				break
			}
			return acceptErr
		}
		select {
		case semaphore <- struct{}{}:
			workers.Add(1)
			go func(conn net.Conn) {
				defer workers.Done()
				defer func() { <-semaphore }()
				defer conn.Close()
				recheckAuthority := func() error {
					if err := configPin.recheck(); err != nil {
						return err
					}
					return keyPin.recheck()
				}
				if recheckAuthority() != nil {
					return
				}
				_ = handleObserverConnectionUsing(ctx, conn, config, key, recheckAuthority, fixedObserverGPUInventory())
			}(connection)
		default:
			_ = connection.Close()
		}
	}
	workers.Wait()
	return nil
}

func RunFixedService() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return Serve(ctx)
}

func verifyFixedSocketDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("fixed observer socket directory is missing or writable by untrusted principals")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("fixed observer socket directory is not root-owned")
	}
	return nil
}

type observerGPUInventorySource struct {
	devices   func(context.Context) ([]gpuDevice, error)
	processes func(context.Context, int) ([]GPUProcess, error)
}

func fixedObserverGPUInventory() observerGPUInventorySource {
	return observerGPUInventorySource{devices: observeGPUDevices, processes: func(ctx context.Context, _ int) ([]GPUProcess, error) { return observeGPUProcesses(ctx) }}
}

func handleObserverConnection(parent context.Context, connection net.Conn, config ObserverConfig, key ed25519.PrivateKey, configSnapshot, keySnapshot []byte) error {
	recheck := func() error {
		if configSnapshot == nil || keySnapshot == nil {
			return nil
		}
		if err := verifyRootPinnedSnapshot(ObserverConfigPath, configSnapshot); err != nil {
			return err
		}
		return verifyRootPinnedSnapshot(ObserverKeyPath, keySnapshot)
	}
	return handleObserverConnectionUsing(parent, connection, config, key, recheck, fixedObserverGPUInventory())
}

// handleObserverConnectionUsing is private test plumbing. Production supplies
// fixedObserverGPUInventory; the kernel-gated fixture may inject only the
// bounded synthetic physical inventory while exercising real peer/process joins.
func handleObserverConnectionUsing(parent context.Context, connection net.Conn, config ObserverConfig, key ed25519.PrivateKey, recheckAuthority func() error, inventory observerGPUInventorySource) error {
	if parent == nil || connection == nil {
		return errors.New("observer connection is incomplete")
	}
	deadline := time.Now().Add(5 * time.Second)
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("observer accepted a non-Unix connection")
	}
	peerCtx, peerCancel := context.WithTimeout(parent, 3*time.Second)
	defer peerCancel()
	peerCred, err := observerPeerCredentials(unixConnection)
	if err != nil {
		return err
	}
	peer, policy, container, err := authorizeObserverPeer(peerCtx, peerCred, config)
	if err != nil {
		return err
	}
	defer peer.close()
	var header [4]byte
	if _, err := io.ReadFull(connection, header[:]); err != nil {
		return err
	}
	length := int(binaryBigEndianUint32(header[:]))
	if length <= 0 || length > observerFrameMax {
		return errors.New("observer request frame length is outside bounds")
	}
	frame := make([]byte, length)
	if _, err := io.ReadFull(connection, frame); err != nil {
		return err
	}
	request, err := DecodeRequest(frame)
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(parent, observerScanTime+observerProbeTime+time.Second)
	defer cancel()
	response, err := observeRequestUsing(requestCtx, request, peer, policy, config.Containers, container, inventory)
	if err != nil {
		return err
	}
	if recheckAuthority != nil {
		if err := recheckAuthority(); err != nil {
			return err
		}
	}
	encoded, err := SignResponse(response, key)
	if err != nil {
		return err
	}
	if err := writeLengthPrefixed(connection, encoded, MaxResponseBytes); err != nil {
		return err
	}
	return nil
}

func observeRequest(ctx context.Context, request Request, peer *heldProcess, policy PeerAuthority, containers []ContainerAuthority, nodeContainer ContainerAuthority) (Response, error) {
	return observeRequestUsing(ctx, request, peer, policy, containers, nodeContainer, fixedObserverGPUInventory())
}

func observeRequestUsing(ctx context.Context, request Request, peer *heldProcess, policy PeerAuthority, containers []ContainerAuthority, nodeContainer ContainerAuthority, inventory observerGPUInventorySource) (Response, error) {
	if ctx == nil || peer == nil {
		return Response{}, errors.New("observer request context or peer is unavailable")
	}
	if err := ValidateRequest(request); err != nil {
		return Response{}, err
	}
	if err := ensureInitialPIDNamespace(); err != nil {
		return Response{}, err
	}
	bootID, err := readBootID()
	if err != nil {
		return Response{}, err
	}
	container, init, worker, err := resolveContainerProcesses(ctx, request, containers, nodeContainer, policy.Role)
	if err != nil {
		return Response{}, err
	}
	defer init.close()
	defer worker.close()
	if worker.value.PID == peer.value.PID {
		return Response{}, errors.New("node peer cannot be attributed as the managed worker")
	}
	if policy.Role == "node-agent" {
		if peer.value.Namespace != init.value.Namespace || !sameCgroupRoot(peer.value.Cgroup, container.CgroupRoot) || peer.uid != container.NodeAgentUID || peer.exe != container.NodeAgentExecutablePath || !strings.EqualFold(peer.exeSHA256, container.NodeAgentExecutableSHA256) {
			return Response{}, errors.New("node agent peer is outside its root-approved container authority")
		}
	}
	if peer.value.Namespace != init.value.Namespace || !sameCgroupRoot(peer.value.Cgroup, container.CgroupRoot) {
		return Response{}, errors.New("authorized peer is not joined to the observed container namespace and host cgroup")
	}
	if !sameCgroupRoot(init.value.Cgroup, container.CgroupRoot) || !sameCgroupRoot(worker.value.Cgroup, container.CgroupRoot) {
		return Response{}, errors.New("container process is outside the root-approved cgroup")
	}
	if inventory.devices == nil || inventory.processes == nil {
		return Response{}, errors.New("observer inventory source is incomplete")
	}
	devices, err := inventory.devices(ctx)
	if err != nil {
		return Response{}, err
	}
	selectedUUID := ""
	for _, device := range devices {
		if device.UUID == request.GPUUUID && strings.EqualFold(device.PCI, request.GPUPCI) {
			if selectedUUID != "" {
				return Response{}, errors.New("requested physical GPU identity is ambiguous")
			}
			selectedUUID = device.UUID
		}
	}
	if selectedUUID == "" {
		return Response{}, errors.New("requested physical GPU is absent from fresh host inventory")
	}
	rows, err := inventory.processes(ctx, worker.value.PID)
	if err != nil {
		return Response{}, err
	}
	selected, err := joinWorkerGPUProcess(rows, worker.value.PID, request.GPUUUID)
	if err != nil {
		return Response{}, err
	}
	peerAfter, err := recheckHeldProcess(ctx, peer)
	if err != nil || !sameStableProcess(peer.value, peerAfter) {
		return Response{}, errors.New("authorized Unix peer changed during observer request")
	}
	initAfter, err := recheckHeldProcess(ctx, init)
	if err != nil || !sameStableProcess(init.value, initAfter) {
		return Response{}, errors.New("container init changed during observer request")
	}
	workerAfter, err := recheckHeldProcess(ctx, worker)
	if err != nil || !sameStableProcess(worker.value, workerAfter) {
		return Response{}, errors.New("container worker changed during observer request")
	}
	bootAfter, err := readBootID()
	if err != nil || bootAfter != bootID {
		return Response{}, errors.New("host boot identity changed during observer request")
	}
	if err := ensureInitialPIDNamespace(); err != nil {
		return Response{}, err
	}
	now := time.Now().UTC()
	requestBytes, err := MarshalRequest(request)
	if err != nil {
		return Response{}, err
	}
	digest := sha256.Sum256(requestBytes)
	response := Response{
		Version: ProtocolVersion, RequestSHA256: hex.EncodeToString(digest[:]), Nonce: request.Nonce,
		BootID: bootID, Role: policy.Role, Peer: peerAfter, Init: initAfter, Worker: workerAfter,
		PeerUID: peer.uid, PeerExecutablePath: peer.exe, PeerExecutableSHA256: peer.exeSHA256,
		GPU: selected, GPUUUID: request.GPUUUID, GPUPCI: request.GPUPCI,
		ObservedAtUnixNS: now.UnixNano(), ExpiresAtUnixNS: now.Add(observerReplyTTL).UnixNano(),
	}
	if err := ValidateResponse(response); err != nil {
		return Response{}, err
	}
	return response, nil
}

func resolveContainerProcesses(ctx context.Context, request Request, authorities []ContainerAuthority, nodeContainer ContainerAuthority, role string) (ContainerAuthority, *heldProcess, *heldProcess, error) {
	scanCtx, cancel := context.WithTimeout(ctx, observerScanTime)
	defer cancel()
	entries, err := os.ReadDir(observerProcRoot)
	if err != nil {
		return ContainerAuthority{}, nil, nil, err
	}
	var matches []struct {
		authority          ContainerAuthority
		initPID, workerPID int
	}
	for index, entry := range entries {
		if index >= observerScanLimit {
			return ContainerAuthority{}, nil, nil, errors.New("host process scan exceeded fixed bound")
		}
		if index%128 == 0 {
			if err := scanCtx.Err(); err != nil {
				return ContainerAuthority{}, nil, nil, err
			}
		}
		if !entry.IsDir() {
			continue
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 1 {
			continue
		}
		procDir := filepath.Join(observerProcRoot, entry.Name())
		chain, statusErr := readNSpid(procDir)
		if statusErr != nil {
			continue
		}
		namespace, namespaceErr := namespaceAt(filepath.Join(procDir, "ns/pid"))
		if namespaceErr != nil || namespace.Device != request.InitNamespaceDev || namespace.Inode != request.InitNamespaceInode || namespace.Filesystem != request.InitNamespaceFS || namespace.NamespaceType != request.InitNamespaceType {
			continue
		}
		if chain[len(chain)-1] != request.InitPID && chain[len(chain)-1] != request.WorkerPID {
			continue
		}
		cgroup, cgroupErr := readCgroup(procDir)
		if cgroupErr != nil {
			continue
		}
		for _, authority := range authorities {
			if (role == "node-agent" || role == "local-observer") && authority.CgroupRoot != nodeContainer.CgroupRoot {
				continue
			}
			if !sameCgroupRoot(cgroup, authority.CgroupRoot) {
				continue
			}
			initPID, workerPID := 0, 0
			if chain[len(chain)-1] == request.InitPID {
				initPID = pid
			}
			if chain[len(chain)-1] == request.WorkerPID {
				workerPID = pid
			}
			matches = append(matches, struct {
				authority          ContainerAuthority
				initPID, workerPID int
			}{authority: authority, initPID: initPID, workerPID: workerPID})
		}
	}
	byAuthority := map[string]struct{ initPID, workerPID int }{}
	for _, match := range matches {
		pair := byAuthority[match.authority.CgroupRoot]
		if match.initPID != 0 {
			if pair.initPID != 0 {
				return ContainerAuthority{}, nil, nil, errors.New("host init NSpid mapping is ambiguous")
			}
			pair.initPID = match.initPID
		}
		if match.workerPID != 0 {
			if pair.workerPID != 0 {
				return ContainerAuthority{}, nil, nil, errors.New("host worker NSpid mapping is ambiguous")
			}
			pair.workerPID = match.workerPID
		}
		byAuthority[match.authority.CgroupRoot] = pair
	}
	var selected *ContainerAuthority
	for _, authority := range authorities {
		pair, ok := byAuthority[authority.CgroupRoot]
		if ok && pair.initPID > 0 && pair.workerPID > 0 {
			if selected != nil {
				return ContainerAuthority{}, nil, nil, errors.New("host process pair matches multiple approved container roots")
			}
			copy := authority
			selected = &copy
		}
	}
	if selected == nil {
		return ContainerAuthority{}, nil, nil, errors.New("host NSpid-to-container process mapping is absent or ambiguous")
	}
	pair := byAuthority[selected.CgroupRoot]
	init, err := openHeldProcess(ctx, pair.initPID)
	if err != nil {
		return ContainerAuthority{}, nil, nil, err
	}
	worker, err := openHeldProcess(ctx, pair.workerPID)
	if err != nil {
		init.close()
		return ContainerAuthority{}, nil, nil, err
	}
	if init.value.NSpid[len(init.value.NSpid)-1] != request.InitPID || worker.value.NSpid[len(worker.value.NSpid)-1] != request.WorkerPID ||
		init.value.StartTicks != request.InitStartTicks || worker.value.StartTicks != request.WorkerStartTicks ||
		init.value.Namespace.Device != request.InitNamespaceDev || init.value.Namespace.Inode != request.InitNamespaceInode ||
		worker.value.Namespace.Device != request.WorkerNamespaceDev || worker.value.Namespace.Inode != request.WorkerNamespaceInode ||
		init.value.Cgroup == "" || worker.value.Cgroup == "" || !sameCgroupRoot(init.value.Cgroup, selected.CgroupRoot) || !sameCgroupRoot(worker.value.Cgroup, selected.CgroupRoot) {
		init.close()
		worker.close()
		return ContainerAuthority{}, nil, nil, errors.New("held container process tuple differs from the requested namespace or root cgroup policy")
	}
	return *selected, init, worker, nil
}

func authorizeObserverPeer(ctx context.Context, credentials *unix.Ucred, config ObserverConfig) (*heldProcess, PeerAuthority, ContainerAuthority, error) {
	return authorizeObserverPeerUsing(ctx, credentials, config, openHeldProcess)
}

// authorizeObserverPeerUsing keeps the test seam below the public production
// path: callers still enter through authorizeObserverPeer and always use the
// original held /proc identity reader.
func authorizeObserverPeerUsing(ctx context.Context, credentials *unix.Ucred, config ObserverConfig,
	open func(context.Context, int) (*heldProcess, error)) (*heldProcess, PeerAuthority, ContainerAuthority, error) {
	if credentials == nil || credentials.Pid <= 1 {
		return nil, PeerAuthority{}, ContainerAuthority{}, errors.New("Unix peer credentials are invalid")
	}
	if open == nil {
		return nil, PeerAuthority{}, ContainerAuthority{}, errors.New("Unix peer identity opener is unavailable")
	}
	peer, err := open(ctx, int(credentials.Pid))
	if err != nil {
		return nil, PeerAuthority{}, ContainerAuthority{}, err
	}
	if peer.uid != credentials.Uid {
		peer.close()
		return nil, PeerAuthority{}, ContainerAuthority{}, errors.New("SO_PEERCRED uid does not match the held process owner")
	}
	peer.uid = credentials.Uid
	var selectedAuthority PeerAuthority
	var selectedContainer ContainerAuthority
	matches := 0
	for _, authority := range config.PeerAuthorities {
		if !observerPeerMatches(peer, credentials.Uid, authority) {
			continue
		}
		container, err := selectObserverPeerContainer(peer, authority, config.Containers)
		if err == nil {
			selectedAuthority = authority
			selectedContainer = container
			matches++
		}
	}
	if matches == 1 {
		return peer, selectedAuthority, selectedContainer, nil
	}
	peer.close()
	if matches > 1 {
		return nil, PeerAuthority{}, ContainerAuthority{}, errors.New("Unix peer matches multiple fixed caller roles")
	}
	return nil, PeerAuthority{}, ContainerAuthority{}, errors.New("Unix peer uid, executable, cgroup, and role do not match the fixed allowlist")
}

func selectObserverPeerContainer(peer *heldProcess, authority PeerAuthority, containers []ContainerAuthority) (ContainerAuthority, error) {
	if peer == nil || peer.value.PID <= 1 || peer.uid != authority.UID || peer.exe != authority.ExecutablePath {
		return ContainerAuthority{}, errors.New("peer does not match the selected role authority")
	}
	var selected ContainerAuthority
	matches := 0
	for _, container := range containers {
		eligible := sameCgroupRoot(peer.value.Cgroup, container.CgroupRoot)
		switch authority.Role {
		case "node-agent":
			eligible = eligible && container.NodeAgentUID == authority.UID && container.NodeAgentExecutablePath == authority.ExecutablePath && strings.EqualFold(container.NodeAgentExecutableSHA256, authority.ExecutableSHA256)
		case "fixed-supervisor":
			eligible = eligible && authority.UID == 0
		case "local-observer":
			eligible = eligible && authority.UID == 0
		default:
			eligible = false
		}
		if !eligible {
			continue
		}
		if matches == 0 {
			selected = container
		}
		matches++
	}
	if matches != 1 {
		return ContainerAuthority{}, fmt.Errorf("peer matches %d root-approved container authorities; exactly one is required", matches)
	}
	return selected, nil
}

func observerPeerMatches(peer *heldProcess, uid uint32, authority PeerAuthority) bool {
	return peer != nil && peer.value.PID > 1 && uid == authority.UID && peer.exe == authority.ExecutablePath && strings.EqualFold(peer.exeSHA256, authority.ExecutableSHA256) && underAnyCgroup(peer.value.Cgroup, authority.CgroupRoots)
}

func openHeldProcess(ctx context.Context, pid int) (*heldProcess, error) {
	if ctx == nil || pid <= 1 {
		return nil, errors.New("held host process PID is invalid")
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	process := &heldProcess{pidfd: pidfd, nsfd: -1}
	failed := func(err error) (*heldProcess, error) { process.close(); return nil, err }
	procDir := filepath.Join(observerProcRoot, strconv.Itoa(pid))
	nsfd, err := unix.Open(filepath.Join(procDir, "ns/pid"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed(err)
	}
	process.nsfd = nsfd
	namespace, err := namespaceFromFD(nsfd)
	if err != nil {
		return failed(err)
	}
	start, err := processStart(procDir, pid)
	if err != nil {
		return failed(err)
	}
	chain, err := readNSpid(procDir)
	if err != nil {
		return failed(err)
	}
	cgroup, err := readCgroup(procDir)
	if err != nil {
		return failed(err)
	}
	exePath, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil || exePath == "" || strings.HasSuffix(exePath, " (deleted)") {
		return failed(errors.New("peer executable path is unavailable or deleted"))
	}
	exeFD, err := unix.Open(filepath.Join(procDir, "exe"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return failed(err)
	}
	file := os.NewFile(uintptr(exeFD), "held-process-executable")
	digest, err := boundedFileSHA256(ctx, file, 256<<20)
	fileInfo, statErr := file.Stat()
	closeErr := file.Close()
	if err != nil || statErr != nil || closeErr != nil || !fileInfo.Mode().IsRegular() {
		return failed(errors.Join(err, statErr, closeErr, errors.New("peer executable is not a regular file")))
	}
	var status unix.Stat_t
	if err := unix.Fstat(int(process.nsfd), &status); err != nil {
		return failed(err)
	}
	var owner unix.Stat_t
	if err := unix.Stat(procDir, &owner); err != nil {
		return failed(err)
	}
	process.exe = filepath.Clean(exePath)
	process.uid = owner.Uid
	process.exeSHA256 = digest
	process.value = Process{PID: pid, StartTicks: start, NSpid: chain, Namespace: namespace, Cgroup: cgroup}
	if err := pidfdStillAlive(process.pidfd); err != nil {
		return failed(err)
	}
	return process, nil
}

func recheckHeldProcess(ctx context.Context, held *heldProcess) (Process, error) {
	if held == nil || held.pidfd < 0 || held.nsfd < 0 {
		return Process{}, errors.New("held process descriptors are missing")
	}
	if err := pidfdStillAlive(held.pidfd); err != nil {
		return Process{}, err
	}
	current, err := openHeldProcess(ctx, held.value.PID)
	if err != nil {
		return Process{}, err
	}
	defer current.close()
	if current.value.StartTicks != held.value.StartTicks || current.value.Namespace != held.value.Namespace || current.value.Cgroup != held.value.Cgroup ||
		current.value.PID != held.value.PID || current.exe != held.exe || !strings.EqualFold(current.exeSHA256, held.exeSHA256) || current.uid != held.uid || !sameIntSlice(current.value.NSpid, held.value.NSpid) {
		return Process{}, errors.New("held process identity changed")
	}
	return current.value, nil
}

func sameStableProcess(a, b Process) bool {
	return a.PID == b.PID && a.StartTicks == b.StartTicks && a.Namespace == b.Namespace && a.Cgroup == b.Cgroup && sameIntSlice(a.NSpid, b.NSpid)
}

func ensureInitialPIDNamespace() error {
	fd, err := unix.Open(filepath.Join(observerProcRoot, "self/ns/pid"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	ns, err := namespaceFromFD(fd)
	if err != nil {
		return err
	}
	if ns.Filesystem != observerNSFSMagic || ns.NamespaceType != uint64(unix.CLONE_NEWPID) || ns.Inode != observerInitPIDNS {
		return errors.New("host observer is not anchored to the initial PID namespace")
	}
	return nil
}

func namespaceAt(path string) (Namespace, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Namespace{}, err
	}
	defer unix.Close(fd)
	return namespaceFromFD(fd)
}

func namespaceFromFD(fd int) (Namespace, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return Namespace{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return Namespace{}, err
	}
	namespaceType, err := namespaceTypeFromFD(fd)
	if err != nil {
		return Namespace{}, err
	}
	if fs.Type != observerNSFSMagic {
		return Namespace{}, errors.New("held descriptor is not a supported namespace")
	}
	return Namespace{Device: uint64(stat.Dev), Inode: stat.Ino, Filesystem: uint64(fs.Type), NamespaceType: namespaceType}, nil
}

func readNSpid(procDir string) ([]int, error) {
	raw, err := readProcBounded(filepath.Join(procDir, "status"), 64<<10)
	if err != nil {
		return nil, err
	}
	return parseNSpidStatus(raw)
}

func parseNSpidStatus(raw []byte) ([]int, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, errors.New("NSpid status is empty or oversized")
	}
	var result []int
	found := false
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 256), 4096)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		if found {
			return nil, errors.New("duplicate NSpid records")
		}
		found = true
		for _, field := range strings.Fields(strings.TrimPrefix(line, "NSpid:")) {
			pid, err := strconv.Atoi(field)
			if err != nil || pid <= 0 || len(result) >= MaxNSpidDepth {
				return nil, errors.New("NSpid chain is malformed or oversized")
			}
			result = append(result, pid)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !found || len(result) == 0 {
		return nil, errors.New("NSpid chain is absent")
	}
	for i, pid := range result {
		if pid == 1 && i != len(result)-1 {
			return nil, errors.New("NSpid chain is ambiguous")
		}
	}
	return result, nil
}

func joinWorkerGPUProcess(rows []GPUProcess, hostPID int, expectedUUID string) (GPUProcess, error) {
	if hostPID <= 1 || !gpuUUIDPattern.MatchString(expectedUUID) || len(rows) > MaxGPUProcessRows {
		return GPUProcess{}, errors.New("worker GPU join request is outside bounds")
	}
	var selected GPUProcess
	count := 0
	for _, row := range rows {
		if row.PID != hostPID {
			continue
		}
		count++
		if row.UUID != expectedUUID {
			return GPUProcess{}, errors.New("worker GPU row belongs to a different physical device")
		}
		selected = row
	}
	if count != 1 || selected.Bytes <= 0 {
		return GPUProcess{}, errors.New("worker has absent, duplicate, or empty physical GPU attribution")
	}
	return selected, nil
}

func processStart(procDir string, pid int) (uint64, error) {
	raw, err := readProcBounded(filepath.Join(procDir, "stat"), 64<<10)
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(raw))
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 1 || close <= open || close+2 >= len(text) {
		return 0, errors.New("process stat record is malformed")
	}
	actualPID, err := strconv.Atoi(strings.TrimSpace(text[:open]))
	fields := strings.Fields(text[close+1:])
	if err != nil || actualPID != pid || len(fields) <= 19 {
		return 0, errors.New("process stat identity is malformed")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return 0, errors.New("process start ticks are invalid")
	}
	return start, nil
}

func readCgroup(procDir string) (string, error) {
	raw, err := readProcBounded(filepath.Join(procDir, "cgroup"), MaxCgroupBytes)
	if err != nil {
		return "", err
	}
	var path string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] == "" {
			return "", errors.New("cgroup record is malformed")
		}
		if parts[0] == "0" && parts[1] == "" {
			if path != "" {
				return "", errors.New("duplicate unified cgroup record")
			}
			path = parts[2]
		}
	}
	if path == "" || len(path) > MaxCgroupBytes || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.Contains(path, "..") || strings.ContainsRune(path, '\x00') {
		return "", errors.New("unified cgroup identity is absent or unsafe")
	}
	return path, nil
}

func readBootID() (string, error) {
	raw, err := readProcBounded(filepath.Join(observerProcRoot, "sys/kernel/random/boot_id"), 128)
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(raw))
	if !bootIDPattern.MatchString(id) {
		return "", errors.New("host boot identity is malformed")
	}
	return id, nil
}

func readProcBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() && info.Mode()&os.ModeType != 0 {
		return nil, errors.New("proc observation is not a bounded pseudo-file")
	}
	b, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(b)) > maximum {
		return nil, errors.New("proc observation exceeded its read bound")
	}
	return b, nil
}

func observeGPUDevices(ctx context.Context) ([]gpuDevice, error) {
	raw, err := runObserverCommand(ctx, observerSMIPath, []string{"--query-gpu=uuid,pci.bus_id", "--format=csv,noheader,nounits"})
	if err != nil {
		return nil, err
	}
	return parseGPUDevices(raw)
}

func parseGPUDevices(raw string) ([]gpuDevice, error) {
	if len(raw) == 0 || len(raw) > observerCommandMax {
		return nil, errors.New("host GPU inventory is empty or oversized")
	}
	var devices []gpuDevice
	seenUUID, seenPCI := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return nil, errors.New("host GPU inventory row is malformed")
		}
		uuid, pci := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if !gpuUUIDPattern.MatchString(uuid) || !pciPattern.MatchString(pci) || seenUUID[uuid] || seenPCI[strings.ToLower(pci)] {
			return nil, errors.New("host GPU inventory has duplicate or malformed identities")
		}
		seenUUID[uuid], seenPCI[strings.ToLower(pci)] = true, true
		devices = append(devices, gpuDevice{UUID: uuid, PCI: pci})
	}
	if len(devices) == 0 || len(devices) > 64 {
		return nil, errors.New("host GPU inventory is empty or exceeds bounds")
	}
	return devices, nil
}

func observeGPUProcesses(ctx context.Context) ([]GPUProcess, error) {
	raw, err := runObserverCommand(ctx, observerSMIPath, []string{"--query-compute-apps=pid,gpu_uuid,used_gpu_memory", "--format=csv,noheader,nounits"})
	if err != nil {
		return nil, err
	}
	return parseGPUProcesses(raw)
}

func parseGPUProcesses(raw string) ([]GPUProcess, error) {
	if len(raw) > observerCommandMax {
		return nil, errors.New("host GPU process inventory exceeded its output bound")
	}
	var rows []GPUProcess
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, errors.New("host GPU process row is malformed")
		}
		pid, pidErr := strconv.Atoi(strings.TrimSpace(parts[0]))
		uuid := strings.TrimSpace(parts[1])
		mib, mibErr := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if pidErr != nil || pid <= 1 || !gpuUUIDPattern.MatchString(uuid) || mibErr != nil || mib <= 0 || mib > (1<<50)/(1<<20) || len(rows) >= MaxGPUProcessRows {
			return nil, errors.New("host GPU process inventory is malformed or oversized")
		}
		rows = append(rows, GPUProcess{PID: pid, UUID: uuid, Bytes: mib << 20})
	}
	return rows, nil
}

type gpuDevice struct{ UUID, PCI string }

func runObserverCommand(parent context.Context, executable string, args []string) (string, error) {
	validArgs := len(args) == 2 && ((args[0] == "--query-gpu=uuid,pci.bus_id" && args[1] == "--format=csv,noheader,nounits") || (args[0] == "--query-compute-apps=pid,gpu_uuid,used_gpu_memory" && args[1] == "--format=csv,noheader,nounits"))
	if parent == nil || executable != observerSMIPath || !validArgs {
		return "", errors.New("observer command is not a fixed bounded inventory")
	}
	ctx, cancel := context.WithTimeout(parent, observerProbeTime)
	defer cancel()
	command := exec.CommandContext(ctx, observerSMIPath, args...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	command.WaitDelay = time.Second
	output := &observerOutput{limit: observerCommandMax}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("fresh fixed NVIDIA inventory failed: %w", err)
	}
	return output.String()
}

type observerOutput struct {
	mu       sync.Mutex
	data     bytes.Buffer
	limit    int
	overflow bool
}

func (o *observerOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	remaining := o.limit - o.data.Len()
	if remaining <= 0 || len(p) > remaining {
		o.overflow = true
		if remaining > 0 {
			_, _ = o.data.Write(p[:remaining])
		}
		return len(p), nil
	}
	return o.data.Write(p)
}
func (o *observerOutput) String() (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.overflow {
		return "", errors.New("fixed NVIDIA inventory exceeded its output bound")
	}
	return o.data.String(), nil
}

func loadObserverConfig(path string) (ObserverConfig, error) {
	raw, err := readRootPinnedFile(path, 64<<10)
	if err != nil {
		return ObserverConfig{}, err
	}
	return decodeObserverConfig(raw)
}

func decodeObserverConfig(raw []byte) (ObserverConfig, error) {
	var config ObserverConfig
	if rejectDuplicateKeys(raw) != nil {
		return config, errors.New("observer policy has duplicate or invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil || requireEOF(decoder) != nil {
		return config, errors.New("observer policy is malformed")
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, raw) {
		return config, errors.New("observer policy is not canonical")
	}
	if err := validateObserverConfig(config); err != nil {
		return config, err
	}
	return config, nil
}

func validateObserverConfig(config ObserverConfig) error {
	if config.Version != ProtocolVersion || config.SocketGID == 0 || len(config.PeerAuthorities) == 0 || len(config.PeerAuthorities) > MaxUnixPeerRoles || len(config.Containers) == 0 || len(config.Containers) > 64 {
		return errors.New("observer policy is missing fixed authorities or outside bounds")
	}
	roles, roots := map[string]bool{}, map[string]bool{}
	for _, authority := range config.PeerAuthorities {
		if authority.Role != "node-agent" && authority.Role != "fixed-supervisor" && authority.Role != "local-observer" || authority.UID == 0 && authority.Role == "node-agent" || (authority.Role == "fixed-supervisor" || authority.Role == "local-observer") && authority.UID != 0 || !filepathIsAbsoluteCanonical(authority.ExecutablePath) || !isLowerHex(authority.ExecutableSHA256, 64) || len(authority.CgroupRoots) == 0 || len(authority.CgroupRoots) > 16 || roles[authority.Role] {
			return errors.New("observer peer authority is invalid or duplicated")
		}
		roles[authority.Role] = true
		for _, root := range authority.CgroupRoots {
			if !validCgroupRoot(root) {
				return errors.New("observer peer cgroup authority is invalid")
			}
		}
	}
	if !roles["node-agent"] || !roles["fixed-supervisor"] {
		return errors.New("observer policy must allow both fixed caller roles")
	}
	if local, ok := peerAuthorityByRole(config.PeerAuthorities, "local-observer"); ok {
		if supervisor, ok := peerAuthorityByRole(config.PeerAuthorities, "fixed-supervisor"); ok && peerAuthoritiesOverlap(local, supervisor) {
			return errors.New("root observer and supervisor authorities overlap")
		}
	}
	for _, container := range config.Containers {
		if !validCgroupRoot(container.CgroupRoot) || container.NodeAgentUID == 0 || !filepathIsAbsoluteCanonical(container.NodeAgentExecutablePath) || !isLowerHex(container.NodeAgentExecutableSHA256, 64) || roots[container.CgroupRoot] {
			return errors.New("observer container authority is invalid or duplicated")
		}
		roots[container.CgroupRoot] = true
	}
	return nil
}

func readRootPinnedFile(path string, maximum int64) ([]byte, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("root-pinned observer file requires root")
	}
	if err := verifyRootDirectoryChain(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "root-pinned-observer-file")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("root-pinned observer descriptor unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("root-pinned observer file has unsafe type or mode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("root-pinned observer file owner, links, or size are unsafe")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != info.Size() {
		return nil, errors.New("root-pinned observer file changed or exceeded bounds")
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("root-pinned observer path changed during read")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || pathStat.Dev != stat.Dev || pathStat.Ino != stat.Ino {
		return nil, errors.New("root-pinned observer path no longer names the opened inode")
	}
	finalInfo, err := file.Stat()
	if err != nil || !samePinnedStat(info, finalInfo) {
		return nil, errors.New("root-pinned observer metadata changed during read")
	}
	return data, nil
}

func samePinnedStat(a, b os.FileInfo) bool {
	if a == nil || b == nil || a.Size() != b.Size() || a.Mode() != b.Mode() {
		return false
	}
	x, xok := a.Sys().(*syscall.Stat_t)
	y, yok := b.Sys().(*syscall.Stat_t)
	return xok && yok && x.Dev == y.Dev && x.Ino == y.Ino && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

func verifyRootPinnedSnapshot(path string, expected []byte) error {
	current, err := readRootPinnedFile(path, int64(len(expected)))
	if err != nil || !bytes.Equal(current, expected) {
		return errors.New("root-approved observer config/key changed after startup snapshot")
	}
	return nil
}

func verifyRootDirectoryChain(path string) error {
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("root-pinned observer parent directory is missing or linked")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("root-pinned observer parent directory is not protected root authority")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

func validCgroupRoot(path string) bool {
	return path != "" && len(path) <= MaxCgroupBytes && filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.Contains(path, "..") && !strings.ContainsRune(path, '\x00')
}
func sameCgroupRoot(path, root string) bool {
	return validCgroupRoot(root) && (path == root || strings.HasPrefix(path, strings.TrimSuffix(root, "/")+"/"))
}
func underAnyCgroup(path string, roots []string) bool {
	for _, root := range roots {
		if sameCgroupRoot(path, root) {
			return true
		}
	}
	return false
}
func sameIntSlice(a, b []int) bool {
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

func observerPeerCredentials(connection *net.UnixConn) (*unix.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if socketErr != nil {
		return nil, socketErr
	}
	return credentials, nil
}

func pidfdStillAlive(fd int) error {
	var poll [1]unix.PollFd
	poll[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	ready, err := unix.Poll(poll[:], 0)
	if err != nil {
		return err
	}
	if ready != 0 || poll[0].Revents != 0 {
		return errors.New("held process has exited")
	}
	return nil
}

func binaryBigEndianUint32(raw []byte) uint32 {
	return uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
}
func writeLengthPrefixed(writer io.Writer, body []byte, maximum int) error {
	if len(body) <= 0 || len(body) > maximum {
		return errors.New("observer response frame is outside bounds")
	}
	header := []byte{byte(uint32(len(body)) >> 24), byte(uint32(len(body)) >> 16), byte(uint32(len(body)) >> 8), byte(len(body))}
	if err := writeObserverFull(writer, header); err != nil {
		return err
	}
	return writeObserverFull(writer, body)
}

func writeObserverFull(writer io.Writer, body []byte) error {
	for len(body) > 0 {
		written, err := writer.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

func boundedFileSHA256(ctx context.Context, file *os.File, maximum int64) (string, error) {
	if ctx == nil || file == nil {
		return "", errors.New("executable hash request is incomplete")
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return "", errors.New("executable hash target is outside bounds")
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := file.Read(buffer)
		if n > 0 {
			total += int64(n)
			if total > maximum {
				return "", errors.New("executable hash exceeded bound")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	if total != info.Size() {
		return "", errors.New("executable changed size while hashing")
	}
	finalInfo, err := file.Stat()
	if err != nil || !samePinnedStat(info, finalInfo) {
		return "", errors.New("executable metadata changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func namespaceTypeFromFD(fd int) (uint64, error) {
	value, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil || value <= 0 {
		return 0, errors.New("held namespace type is unsupported")
	}
	return uint64(value), nil
}
