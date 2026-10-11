//go:build linux && checkpoint_container_kernel

package checkpointgpuobserver

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	kernelFixtureChildEnv            = "CHECKPOINT_GPU_OBSERVER_FIXTURE_CHILD"
	kernelFixtureRootEnv             = "CHECKPOINT_GPU_OBSERVER_FIXTURE_ROOT"
	kernelFixtureUnitEnv             = "CHECKPOINT_GPU_OBSERVER_FIXTURE_UNIT"
	kernelFixturePIDNSEnv            = "CHECKPOINT_GPU_OBSERVER_PARENT_PIDNS"
	kernelFixtureMNTNSEnv            = "CHECKPOINT_GPU_OBSERVER_PARENT_MNTNS"
	kernelFixtureCGNSEnv             = "CHECKPOINT_GPU_OBSERVER_PARENT_CGROUPNS"
	kernelFixtureSocketEnv           = "CHECKPOINT_GPU_OBSERVER_FIXTURE_SOCKET"
	kernelFixturePublicEnv           = "CHECKPOINT_GPU_OBSERVER_FIXTURE_PUBLIC_KEY"
	kernelFixtureScenarioEnv         = "CHECKPOINT_GPU_OBSERVER_FIXTURE_SCENARIO"
	kernelFixtureWorkerEnv           = "CHECKPOINT_GPU_OBSERVER_FIXTURE_WORKER"
	kernelFixtureStartEnv            = "CHECKPOINT_GPU_OBSERVER_FIXTURE_START"
	kernelFixtureFixedHostEnv        = "CHECKPOINT_GPU_OBSERVER_FIXED_HOST"
	kernelFixtureRouteChildEnv       = "CHECKPOINT_OBSERVER_ROUTE_HOST_CHILD"
	kernelFixtureRouteSocketEnv      = "CHECKPOINT_OBSERVER_ROUTE_HOST_SOCKET"
	kernelFixtureRouteConfigEnv      = "CHECKPOINT_OBSERVER_ROUTE_HOST_CONFIG"
	kernelFixtureRouteKeyEnv         = "CHECKPOINT_OBSERVER_ROUTE_HOST_KEY"
	kernelFixtureRouteParentFDEnv    = "CHECKPOINT_OBSERVER_ROUTE_HOST_PARENT_FD"
	kernelFixtureInitialPIDNS uint64 = 4026531836
	kernelFixtureUUID                = "GPU-00000000-0000-0000-0000-000000000019"
	kernelFixturePCI                 = "0000:19:00.0"
)

const kernelFixtureScenarioOrder = "positive\nwrong-peer\nwrong-container\nambiguous-cgroup\nstale-start\nduplicate-gpu-row\nwrong-gpu-row\nwrong-namespace\nexited-worker"
const kernelFixtureFixedAllowlistDenialReason = "Unix peer uid, executable, cgroup, and role do not match the fixed allowlist"

type observerFixtureAcceptedScenario struct {
	name    string
	callErr error
}

type observerFixtureServerResult struct {
	accepted  []observerFixtureAcceptedScenario
	acceptErr error
}

type observerFixtureActiveServerCall struct {
	index  int
	name   string
	conn   *net.UnixConn
	cancel context.CancelFunc
}

func kernelFixtureScenarioNames() []string {
	return strings.Split(kernelFixtureScenarioOrder, "\n")
}

func kernelFixtureExpectedServerReason(scenario string) string {
	switch scenario {
	case "wrong-peer", "wrong-container", "ambiguous-cgroup":
		return kernelFixtureFixedAllowlistDenialReason
	default:
		return ""
	}
}

func boundedObserverFixtureError(err error) string {
	if err == nil {
		return "<nil>"
	}
	clean := strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, err.Error())
	runes := []rune(clean)
	if len(runes) > 320 {
		return string(runes[:320]) + "..."
	}
	return clean
}

func observerFixtureServerSummary(result observerFixtureServerResult) string {
	parts := make([]string, 0, len(result.accepted)+1)
	for index, accepted := range result.accepted {
		parts = append(parts, fmt.Sprintf("accepted[%d]=%s callErr=%q", index+1, accepted.name, boundedObserverFixtureError(accepted.callErr)))
	}
	if result.acceptErr != nil {
		parts = append(parts, "acceptErr="+boundedObserverFixtureError(result.acceptErr))
	}
	if len(parts) == 0 {
		return "no scenario connections accepted"
	}
	return strings.Join(parts, "; ")
}

func TestCheckpointGPUObserverKernelNamespaceFixture(t *testing.T) {
	if value := os.Getenv(kernelFixtureFixedHostEnv); value != "" {
		if value != "1" {
			t.Fatal("fixed-host fixture selector is malformed")
		}
		if err := requireKernelFixtureInitialHostNamespace(); err != nil {
			t.Fatalf("fixed-host initial namespace preflight failed: %v", err)
		}
	}
	switch os.Getenv(kernelFixtureChildEnv) {
	case "route-server":
		runCheckpointGPUObserverRouteServerChild(t)
		return
	case "1":
		runCheckpointGPUObserverNestedNamespaceChild(t)
		return
	case "pid1":
		runCheckpointGPUObserverNestedPID1(t)
		return
	case "client":
		runCheckpointGPUObserverNestedClient(t)
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("kernel fixture requires a root-owned disposable systemd CPU unit")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatalf("local system manager is unavailable for the uniquely scoped CPU fixture: %v", err)
	}
	runCheckpointGPUObserverSystemdFixture(t)
}

func runCheckpointGPUObserverRouteServerChild(t *testing.T) {
	t.Helper()
	if os.Getenv(kernelFixtureRouteChildEnv) != "1" || os.Geteuid() != 0 {
		t.Fatal("composed observer route server child requires its fixed root-only selector")
	}
	configPath, keyPath, socketPath := os.Getenv(kernelFixtureRouteConfigEnv), os.Getenv(kernelFixtureRouteKeyEnv), os.Getenv(kernelFixtureRouteSocketEnv)
	if configPath == "" || keyPath == "" || socketPath == "" || filepath.Clean(configPath) != configPath || filepath.Clean(keyPath) != keyPath || filepath.Clean(socketPath) != socketPath {
		t.Fatal("composed observer route server fixture paths are incomplete or noncanonical")
	}
	parentFD, err := strconv.Atoi(os.Getenv(kernelFixtureRouteParentFDEnv))
	if err != nil || parentFD != 3 {
		t.Fatal("composed host fixture lacks its exact inherited creation-time parent capability")
	}
	defer func() {
		if parentFD >= 0 {
			owned := parentFD
			parentFD = -1
			if err := unix.Close(owned); err != nil {
				t.Errorf("host socket parent capability close outcome is uncertain: %v", err)
			}
		}
	}()
	parentPath := filepath.Dir(socketPath)
	if err := checkpointObserverRouteCheckHeldParent(parentFD, parentPath); err != nil {
		t.Fatalf("composed host socket parent no longer matches its inherited creation capability: %v", err)
	}
	configBytes, err := os.ReadFile(configPath)
	if err != nil || len(configBytes) == 0 || len(configBytes) > 64<<10 {
		t.Fatal("bounded composed host policy is unavailable")
	}
	config, err := decodeObserverConfig(configBytes)
	if err != nil {
		t.Fatalf("composed host policy failed the production parser: %v", err)
	}
	privateBytes, err := os.ReadFile(keyPath)
	if err != nil || len(privateBytes) != ed25519.PrivateKeySize {
		t.Fatal("bounded composed host signing key is unavailable")
	}
	if err := checkpointObserverRouteCheckHeldParent(parentFD, parentPath); err != nil {
		t.Fatalf("composed host socket parent no longer matches its inherited creation capability: %v", err)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create exact composed host listener: %v", err)
	}
	listener.SetUnlinkOnClose(false)
	raw, err := listener.SyscallConn()
	if err != nil {
		original := listener
		listener = nil
		t.Fatalf("retain original composed host listener: %v", errors.Join(err, original.Close()))
	}
	socketFD := -1
	var duplicateErr error
	if err := raw.Control(func(fd uintptr) { socketFD, duplicateErr = unix.Dup(int(fd)) }); err != nil || duplicateErr != nil {
		listenerOwner := listener
		listener = nil
		closeErr := listenerOwner.Close()
		if socketFD >= 0 { descriptor := socketFD; socketFD = -1; closeErr = errors.Join(closeErr, unix.Close(descriptor)) }
		t.Fatalf("duplicate original composed host listener custody: %v", errors.Join(err, duplicateErr, closeErr))
	}
	unix.CloseOnExec(socketFD)
	socketPathFD := -1
	socketPathFD, err = unix.Open(socketPath, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		listenerOwner := listener
		listener = nil
		descriptor := socketFD
		socketFD = -1
		t.Fatalf("retain original bound socket pathname inode independently of listener custody: %v", errors.Join(err, listenerOwner.Close(), unix.Close(descriptor)))
	}
	readyPath := socketPath + ".ready"
	var readyFile *os.File
	cleanupSettled := false
	cleanup := func() error {
		if cleanupSettled { return nil }
		cleanupSettled = true
		return checkpointObserverRouteCloseAndRemoveHostListener(&listener, socketPath, parentPath, &parentFD, &socketFD, &socketPathFD, &readyFile, readyPath)
	}
	defer func() { if !cleanupSettled { if cleanupErr := cleanup(); cleanupErr != nil { t.Errorf("host socket/ready cleanup outcome is uncertain; preserving unmatched objects: %v", cleanupErr) } } }()
	readyFile, err = os.OpenFile(readyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		cleanupErr := cleanup()
		t.Fatalf("create exclusive composed host readiness marker: %v", errors.Join(err, cleanupErr))
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := readyFile.Write([]byte("ready\n")); err != nil { t.Fatal(err) }
	if err := readyFile.Sync(); err != nil { t.Fatal(err) }
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_HOST_READY")
	inventory := observerGPUInventorySource{
		devices: func(context.Context) ([]gpuDevice, error) {
			return []gpuDevice{{UUID: kernelFixtureUUID, PCI: kernelFixturePCI}}, nil
		},
		processes: func(_ context.Context, pid int) ([]GPUProcess, error) {
			return []GPUProcess{{PID: pid, UUID: kernelFixtureUUID, Bytes: 128 << 20}}, nil
		},
	}
	for index := 0; index < 2; index++ {
		connection, err := listener.AcceptUnix()
		if err != nil {
			t.Fatalf("bounded composed host accept %d/2 failed: %v", index+1, err)
		}
		if err := handleObserverConnectionUsing(context.Background(), connection, config, ed25519.PrivateKey(privateBytes), nil, inventory); err != nil {
			closeErr := connection.Close()
			t.Fatalf("actual host observer handler rejected the composed local-observer route: %v (connection settlement: %v)", err, closeErr)
		}
		if err := connection.Close(); err != nil {
			t.Fatalf("close composed host client connection: %v", err)
		}
	}
	if err := cleanup(); err != nil { t.Fatalf("host listener or readiness cleanup did not settle exact creation-owned objects: %v", err) }
	fmt.Println("CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2")
}

func checkpointObserverRouteCheckHeldParent(fd int, path string) error {
	var held unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &held) != nil || held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Uid != 0 || held.Mode&0777 != 0700 {
		return errors.New("inherited original host parent directory capability is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("host socket parent path is absent or became a link")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino || stat.Uid != held.Uid || stat.Gid != held.Gid || uint32(stat.Mode)&unix.S_IFMT != unix.S_IFDIR || uint32(stat.Mode)&0777 != 0700 {
		return errors.New("host socket parent path no longer names the original held directory")
	}
	return nil
}

func checkpointObserverRouteCheckHeldNamedObject(fd int, name string, mode uint32) error {
	var held unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &held) != nil || held.Mode&unix.S_IFMT != mode || held.Uid != 0 || held.Nlink != 1 {
		return errors.New("original host listener/readiness descriptor identity is invalid")
	}
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 { return errors.New("host listener/readiness path is absent or became a link") }
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino || stat.Uid != held.Uid || stat.Gid != held.Gid || uint32(stat.Mode)&unix.S_IFMT != mode || uint64(stat.Nlink) != uint64(held.Nlink) {
		return errors.New("host listener/readiness path no longer names its held creation inode")
	}
	return nil
}

func checkpointObserverRouteCloseAndRemoveHostListener(listener **net.UnixListener, socketPath, parentPath string, parentFD, socketFD, socketPathFD *int, readyFile **os.File, readyPath string) error {
	var result error
	socketCustodyValid := false
	if socketFD != nil && *socketFD >= 0 {
		var listenerStat unix.Stat_t
		if err := unix.Fstat(*socketFD, &listenerStat); err != nil || listenerStat.Mode&unix.S_IFMT != unix.S_IFSOCK || listenerStat.Uid != 0 {
			result = errors.Join(result, errors.New("original listener descriptor custody is invalid"), err)
		} else { socketCustodyValid = true }
	} else { result = errors.Join(result, errors.New("original listener descriptor custody is unavailable")) }
	listenerClosed := listener == nil || *listener == nil
	if listener != nil && *listener != nil {
		owned := *listener
		*listener = nil
		closeErr := owned.Close()
		result = errors.Join(result, closeErr)
		listenerClosed = closeErr == nil
	}
	if listenerClosed && socketCustodyValid {
		if socketPathFD == nil || *socketPathFD < 0 { result = errors.Join(result, errors.New("original bound socket pathname descriptor is unavailable"))
		} else if parentFD == nil || *parentFD < 0 { result = errors.Join(result, errors.New("original protected host parent capability is unavailable"))
		} else if err := checkpointObserverRouteCheckHeldParent(*parentFD, parentPath); err != nil { result = errors.Join(result, err)
		} else if err := checkpointObserverRouteCheckHeldNamedObject(*socketPathFD, socketPath, unix.S_IFSOCK); err != nil { result = errors.Join(result, err)
		} else if err := os.Remove(socketPath); err != nil { result = errors.Join(result, err) }
	}
	if readyFile != nil && *readyFile != nil {
		owned := *readyFile
		*readyFile = nil
		fd := int(owned.Fd())
		if parentFD == nil || *parentFD < 0 { result = errors.Join(result, errors.New("original protected host parent capability is unavailable for readiness cleanup"))
		} else if err := checkpointObserverRouteCheckHeldParent(*parentFD, parentPath); err != nil { result = errors.Join(result, err)
		} else if err := checkpointObserverRouteCheckHeldNamedObject(fd, readyPath, unix.S_IFREG); err != nil { result = errors.Join(result, err)
		} else if err := os.Remove(readyPath); err != nil { result = errors.Join(result, err) }
		result = errors.Join(result, owned.Close())
	}
	if socketFD != nil && *socketFD >= 0 { owned := *socketFD; *socketFD = -1; result = errors.Join(result, unix.Close(owned)) }
	if socketPathFD != nil && *socketPathFD >= 0 { owned := *socketPathFD; *socketPathFD = -1; result = errors.Join(result, unix.Close(owned)) }
	if parentFD != nil && *parentFD >= 0 { owned := *parentFD; *parentFD = -1; result = errors.Join(result, unix.Close(owned)) }
	return result
}

func requireKernelFixtureInitialHostNamespace() error {
	if os.Geteuid() != 0 {
		return errors.New("fixed-host kernel fixture requires root")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("fixed-host kernel fixture requires Linux amd64")
	}
	self, err := namespaceAt("/proc/self/ns/pid")
	if err != nil {
		return fmt.Errorf("read self PID namespace: %w", err)
	}
	init, err := namespaceAt("/proc/1/ns/pid")
	if err != nil {
		return fmt.Errorf("read PID 1 namespace: %w", err)
	}
	if self.Inode != kernelFixtureInitialPIDNS || init.Inode != kernelFixtureInitialPIDNS || self != init {
		return fmt.Errorf("fixed-host PID namespace changed: self=%d PID1=%d expected=%d", self.Inode, init.Inode, kernelFixtureInitialPIDNS)
	}
	return nil
}

type kernelFixtureExecutablePin struct {
	rootDev uint64
	rootIno uint64
	fileDev uint64
	fileIno uint64
	size    int64
	sha256  string
}

func kernelFixtureStat(info os.FileInfo) (*syscall.Stat_t, error) {
	if info == nil {
		return nil, errors.New("fixture stat is missing")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nil, errors.New("fixture stat lacks Linux inode metadata")
	}
	return stat, nil
}

func kernelFixtureFileDigest(fd int, maximum int64) (string, int64, error) {
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var total int64
	for {
		count, err := unix.Pread(fd, buffer, total)
		if count > 0 {
			total += int64(count)
			if total > maximum {
				return "", total, errors.New("fixture executable exceeded its byte bound")
			}
			if _, writeErr := hash.Write(buffer[:count]); writeErr != nil {
				return "", total, writeErr
			}
		}
		if errors.Is(err, io.EOF) || count == 0 && err == nil {
			break
		}
		if err != nil {
			return "", total, err
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), total, nil
}

func kernelFixtureRequireELF64AMD64(fd int) error {
	var header [20]byte
	count, err := unix.Pread(fd, header[:], 0)
	if err != nil || count != len(header) || string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || binary.LittleEndian.Uint16(header[18:20]) != 62 {
		return errors.New("fixture executable is not a bounded little-endian ELF64 amd64 image")
	}
	return nil
}

func publishKernelFixtureExecutable(source, root string, rootInfo os.FileInfo) (string, kernelFixtureExecutablePin, error) {
	const publishedName = "observer-kernel.test"
	if filepath.Base(source) == "" || filepath.Clean(root) != root {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture executable source or root is not canonical")
	}
	rootStat, err := kernelFixtureStat(rootInfo)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootStat.Uid != 0 || rootStat.Nlink != 2 || rootInfo.Mode().Perm() != 0o700 {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture root is not the exact root-owned private directory")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	defer unix.Close(rootFD)
	var heldRoot unix.Stat_t
	if err := unix.Fstat(rootFD, &heldRoot); err != nil || heldRoot.Dev != uint64(rootStat.Dev) || heldRoot.Ino != rootStat.Ino || heldRoot.Uid != 0 || heldRoot.Nlink != 2 {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture root held descriptor identity changed")
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil || !sourceInfo.Mode().IsRegular() || sourceInfo.Mode()&os.ModeSymlink != 0 || sourceInfo.Size() <= 0 || sourceInfo.Size() > 256<<20 {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture self executable is not a bounded regular file")
	}
	sourceStat, err := kernelFixtureStat(sourceInfo)
	if err != nil || sourceStat.Uid != 0 || sourceStat.Nlink != 1 {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture self executable owner or link count is invalid")
	}
	sourceFD, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	defer unix.Close(sourceFD)
	var heldSource unix.Stat_t
	if err := unix.Fstat(sourceFD, &heldSource); err != nil || heldSource.Dev != uint64(sourceStat.Dev) || heldSource.Ino != sourceStat.Ino || heldSource.Size != sourceInfo.Size() || heldSource.Uid != 0 || heldSource.Nlink != 1 {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture self executable held descriptor identity changed")
	}
	if err := kernelFixtureRequireELF64AMD64(sourceFD); err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	sourceHash, sourceBytes, err := kernelFixtureFileDigest(sourceFD, 256<<20)
	if err != nil || sourceBytes != sourceInfo.Size() {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture self executable could not be hashed within its bound")
	}
	if _, err := unix.Seek(sourceFD, 0, io.SeekStart); err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	destFD, err := unix.Openat(rootFD, publishedName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o555)
	if err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	writeErr := error(nil)
	if err := unix.Fchmod(destFD, 0o555); err != nil {
		writeErr = err
	}
	buffer := make([]byte, 64<<10)
	for writeErr == nil {
		count, readErr := unix.Read(sourceFD, buffer)
		if count > 0 {
			for written := 0; written < count; {
				n, err := unix.Write(destFD, buffer[written:count])
				if err != nil || n == 0 {
					writeErr = errors.New("fixture executable copy made no forward progress")
					break
				}
				written += n
			}
		}
		if writeErr != nil {
			break
		}
		if errors.Is(readErr, io.EOF) || count == 0 && readErr == nil {
			break
		}
		if readErr != nil {
			writeErr = readErr
		}
	}
	if writeErr == nil {
		writeErr = unix.Fsync(destFD)
	}
	var publishedStat unix.Stat_t
	if err := unix.Fstat(destFD, &publishedStat); writeErr == nil && err != nil {
		writeErr = err
	}
	closeErr := unix.Close(destFD)
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return "", kernelFixtureExecutablePin{}, writeErr
	}
	var pathStat unix.Stat_t
	if err := unix.Fstatat(rootFD, publishedName, &pathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || pathStat.Dev != publishedStat.Dev || pathStat.Ino != publishedStat.Ino || pathStat.Uid != 0 || pathStat.Nlink != 1 || pathStat.Size != sourceInfo.Size() || pathStat.Mode&0o777 != 0o555 {
		return "", kernelFixtureExecutablePin{}, errors.New("published fixture executable pathname differs from its held inode")
	}
	readFD, err := unix.Openat(rootFD, publishedName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", kernelFixtureExecutablePin{}, err
	}
	publishedHash, publishedBytes, digestErr := kernelFixtureFileDigest(readFD, 256<<20)
	var recheckedStat unix.Stat_t
	statErr := unix.Fstat(readFD, &recheckedStat)
	closeReadErr := unix.Close(readFD)
	if digestErr != nil || statErr != nil || closeReadErr != nil || publishedHash != sourceHash || publishedBytes != sourceBytes || recheckedStat.Dev != publishedStat.Dev || recheckedStat.Ino != publishedStat.Ino || recheckedStat.Uid != 0 || recheckedStat.Nlink != 1 || recheckedStat.Mode&0o777 != 0o555 {
		return "", kernelFixtureExecutablePin{}, errors.New("published fixture executable failed the held-byte or metadata recheck")
	}
	var finalSource unix.Stat_t
	if err := unix.Fstat(sourceFD, &finalSource); err != nil || finalSource.Dev != heldSource.Dev || finalSource.Ino != heldSource.Ino || finalSource.Size != heldSource.Size {
		return "", kernelFixtureExecutablePin{}, errors.New("fixture self executable changed during exact copy")
	}
	return filepath.Join(root, publishedName), kernelFixtureExecutablePin{rootDev: uint64(heldRoot.Dev), rootIno: heldRoot.Ino, fileDev: uint64(publishedStat.Dev), fileIno: publishedStat.Ino, size: publishedStat.Size, sha256: sourceHash}, nil
}

func removePublishedKernelFixtureExecutable(root, published string, rootInfo os.FileInfo, pin kernelFixtureExecutablePin) error {
	if filepath.Dir(published) != root || filepath.Base(published) != "observer-kernel.test" || pin.size <= 0 || len(pin.sha256) != sha256.Size*2 {
		return errors.New("published fixture executable cleanup path or pin is invalid")
	}
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	rootStat, err := kernelFixtureStat(rootInfo)
	if err != nil {
		return err
	}
	var heldRoot unix.Stat_t
	if err := unix.Fstat(rootFD, &heldRoot); err != nil || uint64(heldRoot.Dev) != pin.rootDev || heldRoot.Ino != pin.rootIno || heldRoot.Dev != uint64(rootStat.Dev) || heldRoot.Ino != rootStat.Ino || heldRoot.Uid != 0 || heldRoot.Nlink != 2 {
		return errors.New("fixture root identity changed before published executable cleanup")
	}
	var pathStat unix.Stat_t
	if err := unix.Fstatat(rootFD, "observer-kernel.test", &pathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || uint64(pathStat.Dev) != pin.fileDev || pathStat.Ino != pin.fileIno || pathStat.Uid != 0 || pathStat.Nlink != 1 || pathStat.Size != pin.size || pathStat.Mode&0o777 != 0o555 {
		return errors.New("published fixture executable identity changed before exact unlink")
	}
	fileFD, err := unix.Openat(rootFD, "observer-kernel.test", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	digest, size, digestErr := kernelFixtureFileDigest(fileFD, 256<<20)
	var heldFile unix.Stat_t
	statErr := unix.Fstat(fileFD, &heldFile)
	closeErr := unix.Close(fileFD)
	if digestErr != nil || statErr != nil || closeErr != nil || digest != pin.sha256 || size != pin.size || uint64(heldFile.Dev) != pin.fileDev || heldFile.Ino != pin.fileIno || heldFile.Uid != 0 || heldFile.Nlink != 1 || heldFile.Mode&0o777 != 0o555 {
		return errors.New("published fixture executable bytes or held inode changed before unlink")
	}
	var finalPathStat unix.Stat_t
	if err := unix.Fstatat(rootFD, "observer-kernel.test", &finalPathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil || finalPathStat.Dev != heldFile.Dev || finalPathStat.Ino != heldFile.Ino {
		return errors.New("published fixture executable pathname changed at unlink boundary")
	}
	if err := unix.Unlinkat(rootFD, "observer-kernel.test", 0); err != nil {
		return err
	}
	if err := unix.Fsync(rootFD); err != nil {
		return err
	}
	if err := unix.Fstatat(rootFD, "observer-kernel.test", &finalPathStat, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("published fixture executable remains after exact inode unlink")
	}
	return nil
}

func kernelFixtureNestedServerDenialMarkers(output string) ([]string, bool) {
	const prefix = "FIXTURE_SERVER_AUTH_DENIED:"
	expected := []string{prefix + "wrong-peer", prefix + "wrong-container", prefix + "ambiguous-cgroup"}
	observed := make([]string, 0, len(expected))
	for _, line := range strings.Split(output, "\n") {
		markerStart := strings.Index(line, prefix)
		if markerStart < 0 {
			continue
		}
		if len(observed) >= len(expected) {
			return nil, false
		}
		marker := strings.TrimSuffix(line[markerStart:], "\r")
		observed = append(observed, marker)
	}
	if len(observed) != len(expected) {
		return nil, false
	}
	for index, marker := range observed {
		if marker != expected[index] {
			return nil, false
		}
	}
	return observed, true
}

func runCheckpointGPUObserverSystemdFixture(t *testing.T) {
	t.Helper()
	root, err := os.MkdirTemp("", "checkpoint-gpu-observer-kernel-")
	if err != nil {
		t.Fatal(err)
	}
	createdRoot := root
	var rootInfo os.FileInfo
	publishedPath := ""
	var publishedPin kernelFixtureExecutablePin
	publishedPinned := false
	unit := ""
	unitCreated := false
	rootRemoved := false
	cleanupCertain := true
	cleanupUnit := func() error {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		state, err := runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"show", "--property=LoadState", "--value", unit}, nil)
		if err != nil {
			return fmt.Errorf("query exact transient fixture unit LoadState before cleanup: %w\n%s", err, state)
		}
		if strings.TrimSpace(state) == "not-found" {
			return nil
		}
		if output, err := runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"stop", unit}, nil); err != nil {
			return fmt.Errorf("stop exact transient fixture unit: %w\n%s", err, output)
		}
		state, err = runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"show", "--property=LoadState", "--value", unit}, nil)
		if err != nil {
			return fmt.Errorf("query exact transient fixture unit LoadState: %w\n%s", err, state)
		}
		if strings.TrimSpace(state) == "not-found" {
			return nil
		}
		if strings.TrimSpace(state) == "loaded" {
			active, activeErr := runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"show", "--property=ActiveState", "--value", unit}, nil)
			if activeErr != nil {
				return fmt.Errorf("query exact transient fixture unit ActiveState: %w\n%s", activeErr, active)
			}
			if strings.TrimSpace(active) != "failed" {
				return fmt.Errorf("exact transient fixture unit remains loaded in ActiveState %q", strings.TrimSpace(active))
			}
			if output, resetErr := runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"reset-failed", unit}, nil); resetErr != nil {
				return fmt.Errorf("reset exact failed transient fixture unit: %w\n%s", resetErr, output)
			}
			state, err = runObserverFixtureCommand(cleanupCtx, "/usr/bin/systemctl", []string{"show", "--property=LoadState", "--value", unit}, nil)
			if err != nil {
				return fmt.Errorf("query exact transient fixture unit LoadState after reset: %w\n%s", err, state)
			}
			if strings.TrimSpace(state) == "not-found" {
				return nil
			}
		}
		return fmt.Errorf("exact transient fixture unit LoadState is %q, want not-found", strings.TrimSpace(state))
	}
	defer func() {
		if unitCreated {
			if err := cleanupUnit(); err != nil {
				t.Errorf("exact transient fixture unit cleanup could not be confirmed: %v", err)
				cleanupCertain = false
			} else {
				unitCreated = false
			}
		}
		if !rootRemoved && cleanupCertain {
			if rootInfo == nil || publishedPath != "" && !publishedPinned {
				t.Errorf("private fixture root or published executable pin is unavailable; preserving exact path %q", createdRoot)
				return
			}
			if publishedPinned {
				if err := removePublishedKernelFixtureExecutable(root, publishedPath, rootInfo, publishedPin); err != nil {
					t.Errorf("published self-test executable cleanup is uncertain: %v; preserving exact root %q", err, createdRoot)
					return
				}
				publishedPinned = false
			}
			_ = os.Remove(filepath.Join(createdRoot, "proc"))
			currentRoot, statErr := os.Lstat(createdRoot)
			if statErr != nil || !currentRoot.IsDir() || currentRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, currentRoot) {
				t.Errorf("private fixture root identity changed; preserving exact path %q", createdRoot)
				return
			}
			entries, readErr := os.ReadDir(createdRoot)
			if readErr != nil || len(entries) != 0 {
				t.Errorf("private fixture root contains unexpected or unreadable entries; preserving exact path %q", createdRoot)
				return
			}
			if err := os.Remove(createdRoot); err != nil {
				t.Errorf("exact private fixture directory cleanup failed: %v", err)
				return
			}
			if _, err := os.Lstat(createdRoot); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("exact private fixture directory remains after cleanup: %v", err)
				return
			}
			rootRemoved = true
		}
	}()
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	root = canonicalRoot
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		t.Fatal("private kernel fixture root is not canonical")
	}
	rootInfo, err = os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o700 {
		t.Fatal("private fixture root identity or mode is not exact")
	}
	if os.Getenv(kernelFixtureFixedHostEnv) == "1" && filepath.Dir(root) != "/tmp" {
		t.Fatalf("fixed-host kernel fixture root is not under searchable /tmp: %q", root)
	}
	if os.Getenv(kernelFixtureFixedHostEnv) == "1" {
		tmpInfo, statErr := os.Lstat("/tmp")
		tmpStat, metadataErr := kernelFixtureStat(tmpInfo)
		if statErr != nil || metadataErr != nil || !tmpInfo.IsDir() || tmpInfo.Mode()&os.ModeSymlink != 0 || tmpStat.Uid != 0 || tmpInfo.Mode().Perm() != 0o777 || tmpInfo.Mode()&os.ModeSticky == 0 {
			t.Fatal("fixed-host /tmp is not the existing root-owned sticky searchable parent")
		}
	}
	unitRandom := make([]byte, 12)
	if _, err := rand.Read(unitRandom); err != nil {
		t.Fatal(err)
	}
	unitToken := hex.EncodeToString(unitRandom)
	unit = "checkpoint-gpu-observer-fixture-" + unitToken + ".service"
	if len(unit) > 128 {
		t.Fatal("unique transient unit name exceeded bound")
	}
	if _, err := fmt.Fprintf(os.Stderr, "KERNEL_FIXTURE_IDENTITY: pid=%d unit=%s root=%s\n", os.Getpid(), unit, root); err != nil {
		t.Fatalf("could not publish exact pre-launch fixture identity: %v", err)
	}

	// This unrelated child is the cleanup negative control. The fixture only
	// reads its held PID and confirms it survives the exact transient unit.
	unrelated := exec.Command("/usr/bin/sleep", "180")
	unrelated.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	unrelatedPID := unrelated.Process.Pid
	unrelatedStart, err := processStart(filepath.Join(observerProcRoot, strconv.Itoa(unrelatedPID)), unrelatedPID)
	if err != nil {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
		t.Fatal(err)
	}
	unrelatedFD, err := unix.PidfdOpen(unrelatedPID, 0)
	if err != nil {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
		t.Fatal(err)
	}
	defer func() {
		_ = unix.Close(unrelatedFD)
		if err := unrelated.Process.Kill(); err != nil {
			t.Errorf("kill exact unrelated cleanup-control child: %v", err)
		}
		waitErr := unrelated.Wait()
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) {
			t.Errorf("unrelated cleanup-control child did not reap after SIGKILL: %v", waitErr)
			return
		}
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Errorf("unrelated cleanup-control child exited without the requested SIGKILL: %v", waitErr)
		}
	}()

	pidNS, err := namespaceAt("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	if err := requireKernelFixtureNamespaceType(pidNS, unix.CLONE_NEWPID); err != nil {
		t.Fatal(err)
	}
	mntNS, err := kernelFixtureNamespaceAt("/proc/self/ns/mnt", unix.CLONE_NEWNS)
	if err != nil {
		t.Fatal(err)
	}
	cgroupNS, err := kernelFixtureNamespaceAt("/proc/self/ns/cgroup", unix.CLONE_NEWCGROUP)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	publishedPath = filepath.Join(root, "observer-kernel.test")
	publishedPath, publishedPin, err = publishKernelFixtureExecutable(binary, root, rootInfo)
	if err != nil {
		cleanupCertain = false
		t.Fatalf("bounded self-test executable publication failed; preserving exact fixture path %q: %v", root, err)
	}
	publishedPinned = true
	binary = publishedPath
	if err := os.Chmod(root, 0o711); err != nil {
		cleanupCertain = false
		t.Fatalf("make only the exact private fixture root searchable for UID 65534: %v", err)
	}
	searchableRoot, err := os.Lstat(root)
	if err != nil || !searchableRoot.IsDir() || searchableRoot.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, searchableRoot) || searchableRoot.Mode().Perm() != 0o711 {
		cleanupCertain = false
		t.Fatal("published fixture directory is not the exact root-owned searchable inode")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	args := []string{
		"--system", "--quiet", "--pipe", "--collect", "--wait", "--unit=" + unit,
		"--property=Type=exec", "--property=KillMode=control-group",
		"--setenv=" + kernelFixtureChildEnv + "=1", "--setenv=" + kernelFixtureRootEnv + "=" + root,
		"--setenv=" + kernelFixtureUnitEnv + "=" + unit,
		"--setenv=" + kernelFixturePIDNSEnv + "=" + strconv.FormatUint(pidNS.Inode, 10),
		"--setenv=" + kernelFixtureMNTNSEnv + "=" + strconv.FormatUint(mntNS.Inode, 10),
		"--setenv=" + kernelFixtureCGNSEnv + "=" + strconv.FormatUint(cgroupNS.Inode, 10),
		binary, "-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$", "-test.count=1", "-test.timeout=115s", "-test.v",
	}
	state, err := runObserverFixtureCommand(ctx, "/usr/bin/systemctl", []string{"show", "--property=LoadState", "--value", unit}, nil)
	if err != nil {
		t.Fatalf("could not establish exact transient fixture unit absence before creation: %v\n%s", err, state)
	}
	if strings.TrimSpace(state) != "not-found" {
		t.Fatalf("unique transient fixture unit already has LoadState %q", strings.TrimSpace(state))
	}
	if os.Getenv(kernelFixtureFixedHostEnv) == "1" {
		if err := requireKernelFixtureInitialHostNamespace(); err != nil {
			t.Fatalf("fixed-host initial namespace changed before exact test launch: %v", err)
		}
	}
	unitCreated = true
	output, err := runObserverFixtureCommand(ctx, "/usr/bin/systemd-run", args, nil)
	if err != nil {
		t.Fatalf("uniquely named local CPU namespace unit failed: %v\n%s", err, output)
	}
	if !strings.Contains(output, "NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS") {
		t.Fatalf("kernel fixture did not emit its proof marker:\n%s", output)
	}
	serverReasonMarkers, validServerReasonMarkers := kernelFixtureNestedServerDenialMarkers(output)
	if !validServerReasonMarkers {
		t.Fatal("nested server-denial marker inventory is missing, duplicated, reordered, or unexpected")
	}
	fixtureMarkers := []string{
		"NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS",
		"NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY",
		"FIXTURE_SCENARIO_PASS:positive",
		"FIXTURE_SCENARIO_PASS:wrong-peer",
		"FIXTURE_SCENARIO_PASS:wrong-container",
		"FIXTURE_SCENARIO_PASS:ambiguous-cgroup",
		"FIXTURE_SCENARIO_PASS:stale-start",
		"FIXTURE_SCENARIO_PASS:duplicate-gpu-row",
		"FIXTURE_SCENARIO_PASS:wrong-gpu-row",
		"FIXTURE_SCENARIO_PASS:wrong-namespace",
		"FIXTURE_SCENARIO_PASS:exited-worker",
		"FIXTURE_SCENARIO_DENIED:wrong-peer",
		"FIXTURE_SCENARIO_DENIED:wrong-container",
		"FIXTURE_SCENARIO_DENIED:ambiguous-cgroup",
		"FIXTURE_SCENARIO_DENIED:stale-start",
		"FIXTURE_SCENARIO_DENIED:duplicate-gpu-row",
		"FIXTURE_SCENARIO_DENIED:wrong-gpu-row",
		"FIXTURE_SCENARIO_DENIED:wrong-namespace",
		"FIXTURE_SCENARIO_DENIED:exited-worker",
	}
	for _, marker := range fixtureMarkers {
		if strings.Count(output, marker) != 1 {
			t.Fatalf("nested fixture output must contain exactly one %q marker", marker)
		}
		t.Log(marker)
	}
	for _, marker := range serverReasonMarkers {
		t.Log(marker)
	}
	if err := observerFixturePIDFDAlive(unrelatedFD); err != nil {
		t.Fatalf("unrelated child was touched by exact unit cleanup: %v", err)
	}
	if observed, err := processStart(filepath.Join(observerProcRoot, strconv.Itoa(unrelatedPID)), unrelatedPID); err != nil || observed != unrelatedStart {
		t.Fatalf("unrelated child incarnation changed during fixture: start=%d after=%d err=%v", unrelatedStart, observed, err)
	}
	if err := cleanupUnit(); err != nil {
		t.Fatalf("exact transient fixture unit cleanup could not be confirmed: %v", err)
	}
	unitCreated = false
	t.Log("KERNEL_FIXTURE_UNIT_CLEANUP_PASS:" + unit)
	if !publishedPinned {
		t.Fatal("published self-test executable lost its cleanup inode pin")
	}
	if err := removePublishedKernelFixtureExecutable(root, publishedPath, rootInfo, publishedPin); err != nil {
		cleanupCertain = false
		t.Fatalf("published self-test executable cleanup is uncertain: %v; preserving exact root %q", err, root)
	}
	publishedPinned = false
	t.Log("KERNEL_FIXTURE_PUBLISHED_EXECUTABLE_CLEANUP_PASS")
	if err := os.Remove(filepath.Join(root, "proc")); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private fixture root contains unexpected entries after exact cleanup: %v", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("exact private fixture directory remains: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact private fixture root remains after cleanup: %v", err)
	}
	rootRemoved = true
	t.Log("KERNEL_FIXTURE_PRIVATE_ROOT_CLEANUP_PASS")
}

func runCheckpointGPUObserverNestedNamespaceChild(t *testing.T) {
	t.Helper()
	if os.Getenv(kernelFixtureRootEnv) == "" || os.Getenv(kernelFixtureUnitEnv) == "" {
		t.Fatal("nested fixture is missing its exact unit or private path")
	}
	parentPIDNS := mustKernelFixtureUint(t, kernelFixturePIDNSEnv)
	parentMNTNS := mustKernelFixtureUint(t, kernelFixtureMNTNSEnv)
	parentCGNS := mustKernelFixtureUint(t, kernelFixtureCGNSEnv)
	root := os.Getenv(kernelFixtureRootEnv)
	if err := os.Chmod(root, 0711); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(root, "observer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("create private fixture observer socket: %v", err)
	}
	defer func() { _ = listener.Close(); _ = os.Remove(socketPath) }()
	if err := os.Chown(socketPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetDeadline(time.Now().Add(105 * time.Second)); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executableBytes, err := os.ReadFile(binary)
	if err != nil || len(executableBytes) == 0 || len(executableBytes) > 256<<20 {
		t.Fatalf("bounded fixture executable read failed: %v", err)
	}
	executableHash := sha256.Sum256(executableBytes)
	cgroupRoot, err := readCgroup("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	baseConfig := fixtureObserverConfig(binary, hex.EncodeToString(executableHash[:]), cgroupRoot)
	scenarioDefinitions := map[string]struct {
		name    string
		config  ObserverConfig
		rowMode string
		success bool
	}{
		"positive":          {name: "positive", config: baseConfig, rowMode: "positive", success: true},
		"wrong-peer":        {name: "wrong-peer", config: mutateFixtureNodeUID(baseConfig, 65533), rowMode: "positive"},
		"wrong-container":   {name: "wrong-container", config: mutateFixtureContainerRoot(baseConfig, cgroupRoot+"-wrong"), rowMode: "positive"},
		"ambiguous-cgroup":  {name: "ambiguous-cgroup", config: mutateFixtureAddAncestor(baseConfig, cgroupRoot), rowMode: "positive"},
		"stale-start":       {name: "stale-start", config: baseConfig, rowMode: "positive"},
		"duplicate-gpu-row": {name: "duplicate-gpu-row", config: baseConfig, rowMode: "duplicate"},
		"wrong-gpu-row":     {name: "wrong-gpu-row", config: baseConfig, rowMode: "wrong-gpu"},
		"wrong-namespace":   {name: "wrong-namespace", config: baseConfig, rowMode: "positive"},
		"exited-worker":     {name: "exited-worker", config: baseConfig, rowMode: "positive"},
	}
	scenarios := make([]struct {
		name    string
		config  ObserverConfig
		rowMode string
		success bool
	}, 0, len(scenarioDefinitions))
	seenScenarios := make(map[string]struct{}, len(scenarioDefinitions))
	for _, name := range kernelFixtureScenarioNames() {
		scenario, ok := scenarioDefinitions[name]
		if !ok {
			t.Fatalf("fixture scenario order references missing definition %q", name)
		}
		if _, duplicate := seenScenarios[name]; duplicate {
			t.Fatalf("fixture scenario order repeats %q", name)
		}
		seenScenarios[name] = struct{}{}
		scenarios = append(scenarios, scenario)
	}
	if len(scenarios) != len(scenarioDefinitions) {
		t.Fatal("fixture scenario definitions and shared order differ")
	}
	serverResults := make(chan observerFixtureServerResult, 1)
	var activeServerCallMu sync.Mutex
	var activeServerCall *observerFixtureActiveServerCall
	go func() {
		results := observerFixtureServerResult{accepted: make([]observerFixtureAcceptedScenario, 0, len(scenarios))}
		for index, scenario := range scenarios {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				results.acceptErr = acceptErr
				break
			}
			callCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			activeServerCallMu.Lock()
			activeServerCall = &observerFixtureActiveServerCall{index: index, name: scenario.name, conn: connection, cancel: cancel}
			activeServerCallMu.Unlock()
			mode := scenario.rowMode
			inventory := observerGPUInventorySource{devices: func(context.Context) ([]gpuDevice, error) {
				return []gpuDevice{{UUID: kernelFixtureUUID, PCI: kernelFixturePCI}}, nil
			}, processes: func(_ context.Context, pid int) ([]GPUProcess, error) {
				uuid := kernelFixtureUUID
				if mode == "wrong-gpu" {
					uuid = "GPU-00000000-0000-0000-0000-000000000099"
				}
				rows := 1
				if mode == "duplicate" {
					rows = 2
				}
				result := make([]GPUProcess, rows)
				for i := range result {
					result[i] = GPUProcess{PID: pid, UUID: uuid, Bytes: 128 << 20}
				}
				return result, nil
			}}
			callErr := handleObserverConnectionUsing(callCtx, connection, scenario.config, private, nil, inventory)
			cancel()
			_ = connection.Close()
			activeServerCallMu.Lock()
			activeServerCall = nil
			activeServerCallMu.Unlock()
			results.accepted = append(results.accepted, observerFixtureAcceptedScenario{name: scenario.name, callErr: callErr})
		}
		serverResults <- results
	}()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	childCtx, childCancel := context.WithTimeout(context.Background(), 105*time.Second)
	defer childCancel()
	child := exec.CommandContext(childCtx, self, "-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$", "-test.count=1", "-test.timeout=100s", "-test.v")
	child.Env = replaceFixtureEnvironment(os.Environ(), map[string]string{kernelFixtureChildEnv: "pid1", kernelFixtureRootEnv: root, kernelFixtureUnitEnv: os.Getenv(kernelFixtureUnitEnv), kernelFixturePIDNSEnv: strconv.FormatUint(parentPIDNS, 10), kernelFixtureMNTNSEnv: strconv.FormatUint(parentMNTNS, 10), kernelFixtureCGNSEnv: strconv.FormatUint(parentCGNS, 10), kernelFixtureSocketEnv: socketPath, kernelFixturePublicEnv: hex.EncodeToString(public)})
	child.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 65534, HostID: 65534, Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 0, Size: 1}, {ContainerID: 65534, HostID: 65534, Size: 1}}, GidMappingsEnableSetgroups: false, Pdeathsig: syscall.SIGKILL}
	var output observerFixtureOutput
	output.limit = 128 << 10
	child.Stdout, child.Stderr = &output, &output
	if err := child.Run(); err != nil {
		listenerCloseErr := listener.Close()
		activeServerCallMu.Lock()
		if activeServerCall != nil {
			activeServerCall.cancel()
			_ = activeServerCall.conn.Close()
		}
		activeServerCallMu.Unlock()
		select {
		case result := <-serverResults:
			t.Fatalf("bounded nested PID namespace child failed: %v; observer server: %s; listener close: %s\n%s", err, observerFixtureServerSummary(result), boundedObserverFixtureError(listenerCloseErr), output.String())
		case <-time.After(2 * time.Second):
			activeDescription := "none"
			activeServerCallMu.Lock()
			if activeServerCall != nil {
				activeDescription = fmt.Sprintf("%d:%s", activeServerCall.index+1, activeServerCall.name)
			}
			activeServerCallMu.Unlock()
			t.Fatalf("bounded nested PID namespace child failed: %v; observer server result timed out after 2s; active scenario=%s; listener close: %s\n%s", err, activeDescription, boundedObserverFixtureError(listenerCloseErr), output.String())
		}
	}
	for _, scenario := range []string{"wrong-peer", "wrong-container", "ambiguous-cgroup", "stale-start", "duplicate-gpu-row", "wrong-gpu-row", "wrong-namespace", "exited-worker"} {
		marker := "FIXTURE_SCENARIO_DENIED:" + scenario
		if strings.Count(output.String(), marker) != 1 {
			t.Fatalf("nested client did not emit exactly one validated denial marker %q:\n%s", marker, output.String())
		}
		t.Log(marker)
	}
	results := <-serverResults
	if results.acceptErr != nil {
		t.Fatalf("observer scenario accept failed after %d/%d connections: %s", len(results.accepted), len(scenarios), boundedObserverFixtureError(results.acceptErr))
	}
	if len(results.accepted) != len(scenarios) {
		t.Fatalf("observer accepted %d/%d scenario connections", len(results.accepted), len(scenarios))
	}
	for index, scenario := range scenarios {
		if results.accepted[index].name != scenario.name {
			t.Fatalf("observer scenario order drifted at index %d: got=%s want=%s", index, results.accepted[index].name, scenario.name)
		}
		if scenario.success && results.accepted[index].callErr != nil {
			t.Fatalf("positive production observer join failed: %s", boundedObserverFixtureError(results.accepted[index].callErr))
		}
		if !scenario.success && results.accepted[index].callErr == nil {
			t.Fatalf("production observer accepted negative case %s", scenario.name)
		}
		if expectedReason := kernelFixtureExpectedServerReason(scenario.name); expectedReason != "" {
			if results.accepted[index].callErr == nil || results.accepted[index].callErr.Error() != expectedReason {
				t.Fatalf("production observer rejected %s for the wrong reason: got=%q want=%q", scenario.name, boundedObserverFixtureError(results.accepted[index].callErr), expectedReason)
			}
			t.Log("FIXTURE_SERVER_AUTH_DENIED:" + scenario.name)
		}
		t.Log("FIXTURE_SCENARIO_PASS:" + scenario.name)
	}
	t.Log("NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY")
	const isolationMarker = "NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS"
	if strings.Count(output.String(), isolationMarker) != 1 {
		t.Fatalf("nested child did not prove namespace isolation:\n%s", output.String())
	}
	t.Log(isolationMarker)
}

func fixtureObserverConfig(binary, digest, cgroup string) ObserverConfig {
	return ObserverConfig{Version: ProtocolVersion, SocketGID: 65534, PeerAuthorities: []PeerAuthority{
		{Role: "node-agent", UID: 65534, ExecutablePath: binary, ExecutableSHA256: digest, CgroupRoots: []string{cgroup}},
		{Role: "fixed-supervisor", UID: 0, ExecutablePath: binary, ExecutableSHA256: digest, CgroupRoots: []string{cgroup}},
	}, Containers: []ContainerAuthority{{CgroupRoot: cgroup, NodeAgentUID: 65534, NodeAgentExecutablePath: binary, NodeAgentExecutableSHA256: digest}}}
}

func mutateFixtureNodeUID(config ObserverConfig, uid uint32) ObserverConfig {
	changed := config
	changed.Containers = append([]ContainerAuthority(nil), config.Containers...)
	changed.Containers[0].NodeAgentUID = uid
	return changed
}

func mutateFixtureContainerRoot(config ObserverConfig, root string) ObserverConfig {
	changed := config
	changed.Containers = append([]ContainerAuthority(nil), config.Containers...)
	changed.Containers[0].CgroupRoot = root
	return changed
}

func mutateFixtureAddAncestor(config ObserverConfig, root string) ObserverConfig {
	changed := config
	changed.Containers = append([]ContainerAuthority(nil), config.Containers...)
	ancestor := filepath.Dir(root)
	if ancestor == "/" {
		ancestor = "/system.slice"
	}
	container := config.Containers[0]
	container.CgroupRoot = ancestor
	changed.Containers = append(changed.Containers, container)
	return changed
}

func runCheckpointGPUObserverNestedPID1(t *testing.T) {
	t.Helper()
	if os.Getpid() != 1 {
		t.Fatalf("first process in nested PID namespace is PID %d, expected 1", os.Getpid())
	}
	privateProc := "/proc"
	pidNamespace, err := namespaceAt("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	selfNamespaceFD, err := unix.Open("/proc/self/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(selfNamespaceFD)
	if heldSelfNamespace, err := namespaceFromFD(selfNamespaceFD); err != nil || heldSelfNamespace != pidNamespace {
		t.Fatalf("held PID 1 self namespace descriptor differs: got=%+v want=%+v err=%v", heldSelfNamespace, pidNamespace, err)
	}
	if err := requireKernelFixtureNamespaceType(pidNamespace, unix.CLONE_NEWPID); err != nil {
		t.Fatal(err)
	}
	mountNamespace, err := kernelFixtureNamespaceAt("/proc/self/ns/mnt", unix.CLONE_NEWNS)
	if err != nil {
		t.Fatal(err)
	}
	cgroupNamespace, err := kernelFixtureNamespaceAt("/proc/self/ns/cgroup", unix.CLONE_NEWCGROUP)
	if err != nil {
		t.Fatal(err)
	}
	if pidNamespace.Inode == mustKernelFixtureUint(t, kernelFixturePIDNSEnv) || mountNamespace.Inode == mustKernelFixtureUint(t, kernelFixtureMNTNSEnv) || cgroupNamespace.Inode == mustKernelFixtureUint(t, kernelFixtureCGNSEnv) {
		t.Fatal("nested PID, mount, or cgroup namespace identity did not change")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		t.Fatalf("make nested mount tree private: %v", err)
	}
	if err := verifyMountPropagationPrivateBeforeProcMount(); err != nil {
		t.Fatal(err)
	}
	inheritedProcMount, err := currentKernelFixtureMount(privateProc)
	if err != nil || inheritedProcMount.Filesystem != "proc" {
		t.Fatalf("inherited proc mount identity is unavailable: %+v %v", inheritedProcMount, err)
	}
	if err := unix.Mount("proc", privateProc, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		t.Fatalf("stack namespace-local proc only after namespace and propagation proof: %v", err)
	}
	var ownedProcMount kernelFixtureMountRecord
	ownedProcMountEstablished := false
	defer func() {
		if !ownedProcMountEstablished {
			t.Errorf("exact proc mount identity was not established; leaving private namespace cleanup to fixture process exit")
			return
		}
		if err := unmountOwnedKernelFixtureProc(privateProc, inheritedProcMount, ownedProcMount, mountNamespace, pidNamespace); err != nil {
			t.Errorf("exact private proc mount cleanup is uncertain: %v", err)
		}
	}()
	ownedProcMount, err = currentKernelFixtureMount(privateProc)
	if err != nil || ownedProcMount.ID == inheritedProcMount.ID || ownedProcMount.ParentID != inheritedProcMount.ID || ownedProcMount.Filesystem != "proc" {
		t.Fatalf("new proc mount is not the visible proc mount stacked on the inherited mount: before=%+v after=%+v err=%v", inheritedProcMount, ownedProcMount, err)
	}
	ownedProcMountEstablished = true
	initStart, err := verifyMountedProcIsPrivate(privateProc, inheritedProcMount, ownedProcMount, pidNamespace)
	if err != nil {
		t.Fatal(err)
	}
	initPIDFD, err := unix.PidfdOpen(1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(initPIDFD)
	initNSFD, err := unix.Open(filepath.Join(privateProc, "1/ns/pid"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(initNSFD)
	initHeldNS, err := namespaceFromFD(initNSFD)
	if err != nil || initHeldNS != pidNamespace {
		t.Fatalf("PID 1 namespace fd does not match current namespace: %+v %v", initHeldNS, err)
	}
	worker := exec.Command("/usr/bin/sleep", "90")
	workerPIDFD := -1
	worker.SysProcAttr = &syscall.SysProcAttr{PidFD: &workerPIDFD}
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Wait() }()
	workerReaped := false
	defer func() {
		if !workerReaped && workerPIDFD >= 0 {
			if err := unix.PidfdSendSignal(workerPIDFD, syscall.SIGTERM, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				t.Errorf("could not TERM exact held worker identity during cleanup: %v", err)
			}
			select {
			case <-workerDone:
				workerReaped = true
			case <-time.After(2 * time.Second):
				if err := unix.PidfdSendSignal(workerPIDFD, syscall.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
					t.Errorf("could not KILL exact held worker identity during cleanup: %v", err)
				}
				select {
				case <-workerDone:
					workerReaped = true
				case <-time.After(3 * time.Second):
					t.Errorf("worker Wait/reap remains unconfirmed after held-pidfd TERM/KILL")
				}
			}
		}
		if workerPIDFD >= 0 {
			if err := unix.Close(workerPIDFD); err != nil { t.Errorf("worker pidfd close failed: %v", err) }
			workerPIDFD = -1
		}
	}()
	workerPID := worker.Process.Pid
	workerStart, err := processStart(filepath.Join(privateProc, strconv.Itoa(workerPID)), workerPID)
	if err != nil {
		t.Fatal(err)
	}
	if workerPIDFD < 0 || observerFixturePIDFDAlive(workerPIDFD) != nil {
		t.Fatal("worker atomic creation-time pidfd is absent or not live")
	}
	workerNSFD, err := unix.Open(filepath.Join(privateProc, strconv.Itoa(workerPID), "ns/pid"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(workerNSFD)
	workerNS, err := namespaceFromFD(workerNSFD)
	if err != nil || workerNS != pidNamespace {
		t.Fatalf("worker held PID namespace differs from PID 1: %+v %v", workerNS, err)
	}
	verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, true)
	chain, err := parseNSpidStatus(readFixtureFile(t, filepath.Join(privateProc, strconv.Itoa(workerPID), "status")))
	if err != nil || chain[len(chain)-1] != workerPID {
		t.Fatalf("worker local NSpid association failed: %v %v", chain, err)
	}
	startAfter, err := processStart(filepath.Join(privateProc, strconv.Itoa(workerPID)), workerPID)
	if err != nil || startAfter != workerStart {
		t.Fatalf("worker incarnation changed under held pidfd: before=%d after=%d err=%v", workerStart, startAfter, err)
	}
	if err := observerFixturePIDFDAlive(initPIDFD); err != nil {
		t.Fatal(err)
	}
	if err := observerFixturePIDFDAlive(workerPIDFD); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range kernelFixtureScenarioNames() {
		if scenario == "exited-worker" {
			continue
		}
		verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, true)
		runCheckpointGPUObserverFixtureClient(t, scenario, workerPID, workerStart)
		verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, true)
	}
	if err := unix.PidfdSendSignal(workerPIDFD, syscall.SIGKILL, nil, 0); err != nil {
		t.Fatal(err)
	}
	workerWaitErr := <-workerDone
	workerReaped = true
	if workerWaitErr == nil {
		t.Fatal("SIGKILL worker unexpectedly exited cleanly")
	} else {
		var exitErr *exec.ExitError
		if !errors.As(workerWaitErr, &exitErr) {
			t.Fatalf("worker wait did not reap expected SIGKILL: %v", workerWaitErr)
		}
		status, ok := exitErr.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("worker exited unexpectedly after explicit kill: %v", workerWaitErr)
		}
	}
	verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, false)
	runCheckpointGPUObserverFixtureClient(t, "exited-worker", workerPID, workerStart)
	verifyKernelFixturePID1ProcessState(t, selfNamespaceFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD, pidNamespace, initStart, workerPID, workerStart, false)
	if _, err := verifyMountedProcIsPrivate(privateProc, inheritedProcMount, ownedProcMount, pidNamespace); err != nil {
		t.Fatal(err)
	}
	if finalInitStart, err := processStart(filepath.Join(privateProc, "1"), 1); err != nil || finalInitStart != initStart {
		t.Fatalf("nested PID 1 incarnation changed during fixture: before=%d after=%d err=%v", initStart, finalInitStart, err)
	}
	t.Log("NESTED_PID_MOUNT_CGROUP_FIXTURE_PASS")
}

func runCheckpointGPUObserverFixtureClient(t *testing.T, scenario string, workerPID int, workerStart uint64) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client := exec.CommandContext(ctx, self, "-test.run=^TestCheckpointGPUObserverKernelNamespaceFixture$", "-test.count=1", "-test.timeout=6s", "-test.v")
	client.Env = replaceFixtureEnvironment(os.Environ(), map[string]string{kernelFixtureChildEnv: "client", kernelFixtureScenarioEnv: scenario, kernelFixtureWorkerEnv: strconv.Itoa(workerPID), kernelFixtureStartEnv: strconv.FormatUint(workerStart, 10), kernelFixtureSocketEnv: os.Getenv(kernelFixtureSocketEnv), kernelFixturePublicEnv: os.Getenv(kernelFixturePublicEnv)})
	client.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, NoSetGroups: true}, Pdeathsig: syscall.SIGKILL}
	var output observerFixtureOutput
	output.limit = 32 << 10
	client.Stdout, client.Stderr = &output, &output
	err = client.Run()
	if err != nil {
		t.Fatalf("unprivileged nested observer client did not complete cleanly for %s: %v\n%s", scenario, err, output.String())
	}
	if scenario == "positive" {
		const marker = "NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY"
		if strings.Count(output.String(), marker) != 1 {
			t.Fatalf("client did not verify exactly one signed server response: %s", output.String())
		}
		return
	}
	marker := "FIXTURE_SCENARIO_DENIED:" + scenario
	if strings.Count(output.String(), marker) != 1 {
		t.Fatalf("unprivileged client did not prove one framed denial for %s: %s", scenario, output.String())
	}
	t.Log(marker)
}

func runCheckpointGPUObserverNestedClient(t *testing.T) {
	t.Helper()
	scenario := os.Getenv(kernelFixtureScenarioEnv)
	workerPID, err := strconv.Atoi(os.Getenv(kernelFixtureWorkerEnv))
	if err != nil || workerPID <= 1 {
		t.Fatalf("fixture worker PID invalid: %v", err)
	}
	workerStart, err := strconv.ParseUint(os.Getenv(kernelFixtureStartEnv), 10, 64)
	if err != nil || workerStart == 0 {
		t.Fatalf("fixture worker start ticks invalid: %v", err)
	}
	requestStart := workerStart
	if scenario == "stale-start" {
		requestStart++
	}
	namespace, err := namespaceAt("/proc/self/ns/pid")
	if err != nil {
		t.Fatal(err)
	}
	selfNamespaceFD, err := unix.Open("/proc/self/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(selfNamespaceFD)
	if heldSelfNamespace, err := namespaceFromFD(selfNamespaceFD); err != nil || heldSelfNamespace != namespace {
		t.Fatalf("held fixture client self namespace descriptor differs: got=%+v want=%+v err=%v", heldSelfNamespace, namespace, err)
	}
	if err := requireKernelFixtureNamespaceType(namespace, unix.CLONE_NEWPID); err != nil {
		t.Fatalf("fixture client identity is not a PID namespace: %v", err)
	}
	privateProc := "/proc"
	initStart, err := processStart(filepath.Join(privateProc, "1"), 1)
	if err != nil {
		t.Fatal(err)
	}
	workerPath := filepath.Join(privateProc, strconv.Itoa(workerPID))
	if scenario != "exited-worker" {
		actual, err := processStart(workerPath, workerPID)
		if err != nil || actual != workerStart {
			t.Fatalf("worker incarnation changed before bridge request: %v", err)
		}
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	requestNamespace := namespace
	if scenario == "wrong-namespace" {
		requestNamespace.Inode = ^uint64(0)
	}
	request := Request{Version: ProtocolVersion, Nonce: hex.EncodeToString(nonce), InitPID: 1, InitStartTicks: initStart, InitNamespaceDev: requestNamespace.Device, InitNamespaceInode: requestNamespace.Inode, InitNamespaceFS: requestNamespace.Filesystem, InitNamespaceType: requestNamespace.NamespaceType, WorkerPID: workerPID, WorkerStartTicks: requestStart, WorkerNamespaceDev: requestNamespace.Device, WorkerNamespaceInode: requestNamespace.Inode, WorkerNamespaceFS: requestNamespace.Filesystem, WorkerNamespaceType: requestNamespace.NamespaceType, GPUUUID: kernelFixtureUUID, GPUPCI: kernelFixturePCI}
	encoded, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTimeout("unix", os.Getenv(kernelFixtureSocketEnv), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
	if err := writeFixtureFrame(connection, encoded); err != nil {
		t.Fatal(err)
	}
	responseBytes, headerBytesRead, err := readFixtureFrame(connection, MaxResponseBytes)
	if scenario != "positive" {
		earlyAuthReject := scenario == "wrong-peer" || scenario == "wrong-container" || scenario == "ambiguous-cgroup"
		cleanEOF := headerBytesRead == 0 && errors.Is(err, io.EOF)
		resetBeforeFrame := earlyAuthReject && headerBytesRead == 0 && errors.Is(err, syscall.ECONNRESET)
		if !cleanEOF && !resetBeforeFrame {
			t.Fatalf("negative host-control %s received an unexpected denial response: header_bytes=%d err=%v", scenario, headerBytesRead, err)
		}
		verifyKernelFixtureClientIncarnation(t, selfNamespaceFD, namespace, initStart, workerPath, workerPID, workerStart, scenario != "exited-worker")
		t.Log("FIXTURE_SCENARIO_DENIED:" + scenario)
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	public, err := hex.DecodeString(os.Getenv(kernelFixturePublicEnv))
	if err != nil || len(public) != ed25519.PublicKeySize {
		t.Fatal("fixture public key is invalid")
	}
	response, err := VerifyResponse(responseBytes, ed25519.PublicKey(public), request, time.Now().UTC().UnixNano())
	if err != nil {
		t.Fatalf("host signature did not bind the live namespace worker and peer: %v", err)
	}
	if response.Role != "node-agent" || response.PeerUID != 65534 || response.Peer.NSpid[len(response.Peer.NSpid)-1] != os.Getpid() || response.GPU.Bytes != 128<<20 {
		t.Fatal("signed host observation did not join exact nested client and worker process row")
	}
	verifyKernelFixtureClientIncarnation(t, selfNamespaceFD, namespace, initStart, workerPath, workerPID, workerStart, true)
	t.Log("NESTED_HOST_OBSERVER_SIGNED_JOIN_PASS_SYNTHETIC_ONLY")
}

func verifyKernelFixtureClientIncarnation(t *testing.T, selfNamespaceFD int, expectedNamespace Namespace, initStart uint64, workerPath string, workerPID int, workerStart uint64, workerLive bool) {
	t.Helper()
	heldNamespace, err := namespaceFromFD(selfNamespaceFD)
	if err != nil || heldNamespace != expectedNamespace {
		t.Fatalf("held client self namespace changed across observer exchange: got=%+v want=%+v err=%v", heldNamespace, expectedNamespace, err)
	}
	currentInitStart, err := processStart(filepath.Join("/proc", "1"), 1)
	if err != nil || currentInitStart != initStart {
		t.Fatalf("local PID 1 incarnation changed across observer exchange: before=%d after=%d err=%v", initStart, currentInitStart, err)
	}
	if workerLive {
		currentWorkerStart, err := processStart(workerPath, workerPID)
		if err != nil || currentWorkerStart != workerStart {
			t.Fatalf("live worker incarnation changed across observer exchange: before=%d after=%d err=%v", workerStart, currentWorkerStart, err)
		}
	}
}

func writeFixtureFrame(writer io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxRequestBytes {
		return errors.New("fixture request frame is outside bounds")
	}
	header := []byte{byte(len(raw) >> 24), byte(len(raw) >> 16), byte(len(raw) >> 8), byte(len(raw))}
	if err := writeObserverFull(writer, header); err != nil {
		return err
	}
	return writeObserverFull(writer, raw)
}
func readFixtureFrame(reader io.Reader, maximum int) ([]byte, int, error) {
	var header [4]byte
	headerBytesRead, err := io.ReadFull(reader, header[:])
	if err != nil {
		return nil, headerBytesRead, err
	}
	length := int(binaryBigEndianUint32(header[:]))
	if length <= 0 || length > maximum {
		return nil, headerBytesRead, errors.New("fixture response frame is outside bounds")
	}
	raw := make([]byte, length)
	_, err = io.ReadFull(reader, raw)
	return raw, headerBytesRead, err
}

func verifyMountPropagationPrivateBeforeProcMount() error {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("mountinfo is unavailable or outside bounds")
	}
	foundRoot := false
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 {
			return errors.New("root mountinfo record is malformed")
		}
		for _, optional := range fields[6:separator] {
			if strings.HasPrefix(optional, "shared:") || strings.HasPrefix(optional, "master:") || strings.HasPrefix(optional, "propagate_from:") {
				return errors.New("mount tree contains a shared or slave propagation point")
			}
		}
		if fields[4] == "/" {
			foundRoot = true
		}
	}
	if !foundRoot {
		return errors.New("root mountinfo record is absent")
	}
	return nil
}

type kernelFixtureMountRecord struct {
	ID         uint64
	ParentID   uint64
	MountPoint string
	Filesystem string
	Optional   []string
}

func readKernelFixtureMountInfo() ([]kernelFixtureMountRecord, error) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return nil, errors.New("mountinfo is unavailable or outside bounds")
	}
	records := make([]kernelFixtureMountRecord, 0, 64)
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, errors.New("mountinfo record is malformed")
		}
		separator := -1
		for index, field := range fields {
			if field == "-" {
				separator = index
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) {
			return nil, errors.New("mountinfo record has no filesystem separator or type")
		}
		id, idErr := strconv.ParseUint(fields[0], 10, 64)
		parentID, parentErr := strconv.ParseUint(fields[1], 10, 64)
		if idErr != nil || parentErr != nil || id == 0 || parentID == 0 {
			return nil, errors.New("mountinfo record has an invalid mount or parent ID")
		}
		records = append(records, kernelFixtureMountRecord{ID: id, ParentID: parentID, MountPoint: fields[4], Filesystem: fields[separator+1], Optional: append([]string(nil), fields[6:separator]...)})
	}
	if len(records) == 0 {
		return nil, errors.New("mountinfo has no mount records")
	}
	return records, nil
}

func currentKernelFixtureMount(path string) (kernelFixtureMountRecord, error) {
	var stat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, path, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_MNT_ID, &stat); err != nil {
		return kernelFixtureMountRecord{}, err
	}
	if stat.Mask&unix.STATX_MNT_ID == 0 || stat.Mnt_id == 0 {
		return kernelFixtureMountRecord{}, errors.New("statx did not report a mount ID")
	}
	records, err := readKernelFixtureMountInfo()
	if err != nil {
		return kernelFixtureMountRecord{}, err
	}
	var found kernelFixtureMountRecord
	count := 0
	for _, record := range records {
		if record.ID == stat.Mnt_id {
			found = record
			count++
		}
	}
	if count != 1 || found.MountPoint != path {
		return kernelFixtureMountRecord{}, errors.New("visible path mount ID has no unique exact mountinfo record")
	}
	return found, nil
}

func verifyMountedProcIsPrivate(path string, inherited, owned kernelFixtureMountRecord, expectedPIDNS Namespace) (uint64, error) {
	visible, err := currentKernelFixtureMount(path)
	if err != nil || visible.ID != owned.ID || visible.ParentID != inherited.ID || visible.Filesystem != "proc" || owned.ID == inherited.ID {
		return 0, fmt.Errorf("visible proc mount identity is not the exact owned top mount: visible=%+v inherited=%+v owned=%+v err=%v", visible, inherited, owned, err)
	}
	for _, optional := range visible.Optional {
		if strings.HasPrefix(optional, "shared:") || strings.HasPrefix(optional, "master:") || strings.HasPrefix(optional, "propagate_from:") {
			return 0, errors.New("fixture proc mount is shared or slave")
		}
	}
	selfTarget, err := os.Readlink(filepath.Join(path, "self"))
	if err != nil || selfTarget != "1" {
		return 0, fmt.Errorf("fixture proc self link does not identify local PID 1: target=%q err=%v", selfTarget, err)
	}
	initNamespace, err := namespaceAt(filepath.Join(path, "1/ns/pid"))
	if err != nil || initNamespace != expectedPIDNS {
		return 0, fmt.Errorf("mounted proc PID 1 namespace differs from held nested PID namespace: got=%+v want=%+v err=%v", initNamespace, expectedPIDNS, err)
	}
	selfNamespace, err := namespaceAt(filepath.Join(path, "self/ns/pid"))
	if err != nil || selfNamespace != expectedPIDNS {
		return 0, fmt.Errorf("mounted proc self namespace differs from held nested PID namespace: got=%+v want=%+v err=%v", selfNamespace, expectedPIDNS, err)
	}
	initStart, err := processStart(filepath.Join(path, "1"), 1)
	if err != nil {
		return 0, fmt.Errorf("mounted proc does not expose local PID 1: %w", err)
	}
	selfStart, err := processStart(filepath.Join(path, "self"), 1)
	if err != nil || selfStart != initStart {
		return 0, fmt.Errorf("mounted proc PID 1 and self start ticks differ: init=%d self=%d err=%v", initStart, selfStart, err)
	}
	return initStart, nil
}

func unmountOwnedKernelFixtureProc(path string, inherited, owned kernelFixtureMountRecord, expectedMountNS, expectedPIDNS Namespace) error {
	mountNS, err := kernelFixtureNamespaceAt("/proc/self/ns/mnt", unix.CLONE_NEWNS)
	if err != nil || mountNS != expectedMountNS {
		return fmt.Errorf("mount namespace changed before fixture proc cleanup: got=%+v want=%+v err=%v", mountNS, expectedMountNS, err)
	}
	pidNS, err := namespaceAt("/proc/self/ns/pid")
	if err != nil || pidNS != expectedPIDNS {
		return fmt.Errorf("PID namespace changed before fixture proc cleanup: got=%+v want=%+v err=%v", pidNS, expectedPIDNS, err)
	}
	visible, err := currentKernelFixtureMount(path)
	if err != nil || visible.ID != owned.ID || visible.ParentID != inherited.ID || visible.Filesystem != "proc" {
		return fmt.Errorf("refusing to unmount uncertain fixture proc target: visible=%+v inherited=%+v owned=%+v err=%v", visible, inherited, owned, err)
	}
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil {
		return fmt.Errorf("unmount exact owned proc top mount %d: %w", owned.ID, err)
	}
	records, err := readKernelFixtureMountInfo()
	if err != nil {
		return fmt.Errorf("confirm owned proc mount %d absence: %w", owned.ID, err)
	}
	for _, record := range records {
		if record.ID == owned.ID {
			return fmt.Errorf("owned proc mount ID %d remains after unmount", owned.ID)
		}
	}
	visible, err = currentKernelFixtureMount(path)
	if err != nil || visible.ID != inherited.ID || visible.Filesystem != inherited.Filesystem {
		return fmt.Errorf("inherited proc mount did not become visible after owned top mount cleanup: visible=%+v inherited=%+v err=%v", visible, inherited, err)
	}
	return nil
}

func replaceFixtureEnvironment(existing []string, replacements map[string]string) []string {
	result := make([]string, 0, len(existing)+len(replacements))
	for _, item := range existing {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		if _, replace := replacements[key]; replace {
			continue
		}
		result = append(result, item)
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	return result
}

func mustKernelFixtureUint(t *testing.T, name string) uint64 {
	t.Helper()
	value, err := strconv.ParseUint(os.Getenv(name), 10, 64)
	if err != nil || value == 0 {
		t.Fatalf("fixture namespace marker %s is invalid", name)
	}
	return value
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 64<<10+1))
	if err != nil || len(data) > 64<<10 {
		t.Fatal("bounded fixture proc read failed")
	}
	return data
}

func observerFixturePIDFDAlive(fd int) error {
	var poll [1]unix.PollFd
	poll[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN}
	ready, err := unix.Poll(poll[:], 0)
	if err != nil {
		return err
	}
	if ready != 0 || poll[0].Revents != 0 {
		return errors.New("held fixture PID exited before join recheck")
	}
	return nil
}

func observerFixturePIDFDExited(fd int) error {
	if fd < 0 {
		return errors.New("held fixture pidfd is invalid")
	}
	// POLLRDNORM is 0x0040 per Linux v6.8 include/uapi/asm-generic/poll.h:
	// https://raw.githubusercontent.com/torvalds/linux/v6.8/include/uapi/asm-generic/poll.h
	// x/sys/unix v0.30.0 does not export POLLRDNORM.
	const fixturePollRDNORM int16 = 0x0040
	var poll [1]unix.PollFd
	poll[0] = unix.PollFd{Fd: int32(fd), Events: unix.POLLIN | unix.POLLHUP}
	ready, err := unix.Poll(poll[:], 0)
	if err != nil {
		return err
	}
	revents := poll[0].Revents
	if ready != 1 || revents&unix.POLLIN == 0 || revents&(unix.POLLERR|unix.POLLNVAL) != 0 || revents&^(unix.POLLIN|unix.POLLHUP|fixturePollRDNORM) != 0 {
		return fmt.Errorf("held fixture pidfd did not report clean post-reap readiness: ready=%d revents=%#x", ready, revents)
	}
	file, err := os.Open(filepath.Join("/proc/self/fdinfo", strconv.Itoa(fd)))
	if err != nil {
		return fmt.Errorf("open bounded held-pidfd info: %w", err)
	}
	defer file.Close()
	info, err := io.ReadAll(io.LimitReader(file, (4<<10)+1))
	if err != nil {
		return fmt.Errorf("read bounded held-pidfd info: %w", err)
	}
	if len(info) > 4<<10 {
		return errors.New("held-pidfd info exceeds its fixed bound")
	}
	pidLines := 0
	for _, line := range strings.Split(string(info), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Pid:" {
			continue
		}
		pidLines++
		if len(fields) != 2 || fields[1] != "-1" {
			return errors.New("held pidfd still identifies a live or unreaped process")
		}
	}
	if pidLines != 1 {
		return fmt.Errorf("held pidfd info must contain exactly one original-process absence record, got %d", pidLines)
	}
	return nil
}

func verifyKernelFixturePID1ProcessState(t *testing.T, selfNSFD, initNSFD, workerNSFD, initPIDFD, workerPIDFD int, expectedNamespace Namespace, initStart uint64, workerPID int, workerStart uint64, workerLive bool) {
	t.Helper()
	for name, fd := range map[string]int{"self": selfNSFD, "init": initNSFD, "worker": workerNSFD} {
		namespace, err := namespaceFromFD(fd)
		if err != nil || namespace != expectedNamespace {
			t.Fatalf("held %s namespace descriptor changed across observer exchange: got=%+v want=%+v err=%v", name, namespace, expectedNamespace, err)
		}
		if err := requireKernelFixtureNamespaceType(namespace, unix.CLONE_NEWPID); err != nil {
			t.Fatalf("held %s namespace descriptor has wrong type: %v", name, err)
		}
	}
	if err := observerFixturePIDFDAlive(initPIDFD); err != nil {
		t.Fatalf("nested PID 1 exited during observer exchange: %v", err)
	}
	currentInitStart, err := processStart(filepath.Join("/proc", "1"), 1)
	if err != nil || currentInitStart != initStart {
		t.Fatalf("nested PID 1 incarnation changed across observer exchange: before=%d after=%d err=%v", initStart, currentInitStart, err)
	}
	workerPath := filepath.Join("/proc", strconv.Itoa(workerPID))
	if workerLive {
		if err := observerFixturePIDFDAlive(workerPIDFD); err != nil {
			t.Fatalf("live fixture worker exited during observer exchange: %v", err)
		}
		currentWorkerStart, err := processStart(workerPath, workerPID)
		if err != nil || currentWorkerStart != workerStart {
			t.Fatalf("worker incarnation changed across observer exchange: before=%d after=%d err=%v", workerStart, currentWorkerStart, err)
		}
		return
	}
	if err := observerFixturePIDFDExited(workerPIDFD); err != nil {
		t.Fatalf("fixture worker did not retain the expected exited state: %v", err)
	}
	if currentWorkerStart, err := processStart(workerPath, workerPID); err == nil {
		if currentWorkerStart == workerStart {
			t.Fatalf("worker start ticks still identify the exited incarnation: %d", currentWorkerStart)
		}
		t.Fatalf("worker PID was reused before exited state could be confirmed: previous=%d current=%d", workerStart, currentWorkerStart)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatalf("cannot distinguish exited worker from an uncertain proc read: %v", err)
	}
}

func kernelFixtureNamespaceAt(path string, expectedType int) (Namespace, error) {
	if expectedType != unix.CLONE_NEWPID && expectedType != unix.CLONE_NEWNS && expectedType != unix.CLONE_NEWCGROUP {
		return Namespace{}, errors.New("fixture requested an unsupported namespace type")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Namespace{}, err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return Namespace{}, err
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return Namespace{}, err
	}
	if filesystem.Type != observerNSFSMagic {
		return Namespace{}, errors.New("fixture descriptor is not on NSFS")
	}
	namespaceType, err := unix.IoctlRetInt(fd, unix.NS_GET_NSTYPE)
	if err != nil {
		return Namespace{}, err
	}
	if namespaceType != expectedType {
		return Namespace{}, fmt.Errorf("fixture namespace type is %d, want %d", namespaceType, expectedType)
	}
	return Namespace{Device: uint64(stat.Dev), Inode: stat.Ino, Filesystem: uint64(filesystem.Type), NamespaceType: uint64(namespaceType)}, nil
}

func requireKernelFixtureNamespaceType(namespace Namespace, expectedType int) error {
	if namespace.Filesystem != observerNSFSMagic || namespace.NamespaceType != uint64(expectedType) {
		return fmt.Errorf("fixture namespace identity has filesystem/type %d/%d, want %d/%d", namespace.Filesystem, namespace.NamespaceType, observerNSFSMagic, expectedType)
	}
	return nil
}

type observerFixtureOutput struct {
	mu sync.Mutex
	bytes.Buffer
	limit int
}

func (output *observerFixtureOutput) Write(p []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.limit <= 0 || output.Len()+len(p) > output.limit {
		return 0, errors.New("fixture command output exceeded its bound")
	}
	return output.Buffer.Write(p)
}

func (output *observerFixtureOutput) String() string {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.Buffer.String()
}

func runObserverFixtureCommand(ctx context.Context, executable string, args []string, environment []string) (string, error) {
	if executable != "/usr/bin/systemd-run" && executable != "/usr/bin/systemctl" && executable != "/usr/bin/sleep" {
		return "", errors.New("fixture attempted an unreviewed executable")
	}
	command := exec.CommandContext(ctx, executable, args...)
	if environment != nil {
		command.Env = append(os.Environ(), environment...)
	}
	command.WaitDelay = time.Second
	var output observerFixtureOutput
	output.limit = 64 << 10
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return output.String(), err
	}
	return output.String(), nil
}
