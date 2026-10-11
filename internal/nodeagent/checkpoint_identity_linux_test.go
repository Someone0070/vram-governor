//go:build linux

package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const fixturePID = 4242
const fixtureSocket = uint64(987654)

type checkpointIdentityFixture struct {
	root      string
	req       CheckpointIdentityRequest
	source    checkpointLinuxSource
	model     string
	exe       string
	modelSize int64
	exeSize   int64
	device    uint64
	inode     uint64
}

func newCheckpointIdentityFixture(t *testing.T) *checkpointIdentityFixture {
	t.Helper()
	root := t.TempDir()
	modelRoot := filepath.Join(root, "models")
	if err := os.MkdirAll(modelRoot, 0700); err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(modelRoot, "demo.gguf")
	modelBytes := []byte(strings.Repeat("gguf-model-fixture-", 4096))
	if err := os.WriteFile(modelPath, modelBytes, 0600); err != nil {
		t.Fatal(err)
	}
	exePath := filepath.Join(root, "llama-server")
	exeBytes := []byte(strings.Repeat("binary-fixture-", 2048))
	if err := os.WriteFile(exePath, exeBytes, 0700); err != nil {
		t.Fatal(err)
	}
	procRoot := filepath.Join(root, "proc")
	procDir := filepath.Join(procRoot, fmt.Sprint(fixturePID))
	for _, dir := range []string{filepath.Join(procRoot, "net"), filepath.Join(procRoot, "sys/kernel/random"), filepath.Join(procDir, "fd")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(procRoot, "sys/kernel/random/boot_id"), []byte("00000000-0000-0000-0000-000000000001\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeCheckpointFixtureStat(t, procDir, 123456)
	if err := os.Symlink(exePath, filepath.Join(procDir, "exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fmt.Sprintf("socket:[%d]", fixtureSocket), filepath.Join(procDir, "fd/3")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "net/tcp"), []byte(checkpointFixtureTCPRow("0100007F", 8080, fixtureSocket)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(procRoot, "net/tcp6"), []byte(" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(modelPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("fixture file stat does not expose Linux identity")
	}
	maps := filepath.Join(procDir, "maps")
	writeCheckpointFixtureMaps(t, maps, info.Size(), uint64(stat.Dev), stat.Ino)
	modelSum, exeSum := sha256.Sum256(modelBytes), sha256.Sum256(exeBytes)
	return &checkpointIdentityFixture{
		root: procRoot, model: modelPath, exe: exePath, modelSize: info.Size(), exeSize: int64(len(exeBytes)), device: uint64(stat.Dev), inode: stat.Ino,
		req: CheckpointIdentityRequest{
			Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit,
			ModelPath: modelPath, ExpectedModelSHA256: hex.EncodeToString(modelSum[:]),
			ApprovedModelRoots: []string{modelRoot}, ExpectedExecutableSHA256: hex.EncodeToString(exeSum[:]),
		},
		source: checkpointLinuxSource{
			procRoot: procRoot,
			mainPID:  func(context.Context, string) (int, error) { return fixturePID, nil },
		},
	}
}

func writeCheckpointFixtureStat(t *testing.T, procDir string, start uint64) {
	t.Helper()
	fields := []string{"S"}
	for i := 1; i < 19; i++ {
		fields = append(fields, "0")
	}
	fields = append(fields, fmt.Sprint(start))
	line := fmt.Sprintf("%d (llama-server fixture) %s\n", fixturePID, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(procDir, "stat"), []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
}

func checkpointFixtureTCPRow(addr string, port uint16, inode uint64) string {
	return fmt.Sprintf(" sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n 0: %s:%04X 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 %d 1\n", addr, port, inode)
}

func writeCheckpointFixtureMaps(t *testing.T, path string, size int64, device, inode uint64) {
	t.Helper()
	major, minor := unix.Major(device), unix.Minor(device)
	line := fmt.Sprintf("7f0000000000-%x r--p 00000000 %02x:%02x %d /models/demo.gguf\n", uint64(0x7f0000000000)+uint64(size), major, minor, inode)
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
}

func observeCheckpointFixture(t *testing.T, fixture *checkpointIdentityFixture) (CheckpointLocalIdentity, error) {
	t.Helper()
	return observeCheckpointIdentityLinux(context.Background(), fixture.req, fixture.req.Endpoint, net.ParseIP("127.0.0.1"), 8080, fixture.source)
}

func TestCheckpointLocalIdentityLinuxObserverAcceptsExactMappedArtifact(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	identity, err := observeCheckpointFixture(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != fixturePID || identity.ProcessStartTicks != 123456 || identity.ListenerPort != 8080 || identity.ModelInode != f.inode || identity.ObservedMappedBytes != f.modelSize {
		t.Fatalf("observer returned incomplete process/artifact identity: %+v", identity)
	}
	if identity.HasVerifiedLoadProvenance() {
		t.Fatal("current mapping observations must not claim historical model-load provenance")
	}
	if identity.Fingerprint == "" || identity.ExecutableSHA256 != f.req.ExpectedExecutableSHA256 || identity.ModelSHA256 != f.req.ExpectedModelSHA256 {
		t.Fatalf("observer did not bind the allowlisted executable and model: %+v", identity)
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsListenerOwnershipMismatch(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	if err := os.Remove(filepath.Join(f.root, fmt.Sprint(fixturePID), "fd/3")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[123]", filepath.Join(f.root, fmt.Sprint(fixturePID), "fd/3")); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a service process that did not own the listener socket")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsAmbiguousListeners(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, "net/tcp")
	row := checkpointFixtureTCPRow("0100007F", 8080, fixtureSocket)
	if err := os.WriteFile(path, []byte(row+strings.SplitN(row, "\n", 2)[1]), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted ambiguous SO_REUSEPORT-style listener sockets")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsUnmappedArtifact(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
	writeCheckpointFixtureMaps(t, path, f.modelSize, f.device, f.inode+1)
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a model found only on disk but not mapped in the listener process")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsIncompleteMapping(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
	writeCheckpointFixtureMaps(t, path, f.modelSize/2, f.device, f.inode)
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a partial model mapping")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsUnreadableMapping(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
	major, minor := unix.Major(f.device), unix.Minor(f.device)
	line := fmt.Sprintf("7f0000000000-%x ---p 00000000 %02x:%02x %d /models/demo.gguf\n", uint64(0x7f0000000000)+uint64(f.modelSize), major, minor, f.inode)
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a PROT_NONE mapping as readable model bytes")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsWritableMapping(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
	major, minor := unix.Major(f.device), unix.Minor(f.device)
	line := fmt.Sprintf("7f0000000000-%x rw-p 00000000 %02x:%02x %d /models/demo.gguf\n", uint64(0x7f0000000000)+uint64(f.modelSize), major, minor, f.inode)
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a writable GGUF mapping")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsSharedMapping(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	path := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
	major, minor := unix.Major(f.device), unix.Minor(f.device)
	line := fmt.Sprintf("7f0000000000-%x r--s 00000000 %02x:%02x %d /models/demo.gguf\n", uint64(0x7f0000000000)+uint64(f.modelSize), major, minor, f.inode)
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a shared GGUF mapping")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsChangedProcessIncarnation(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	procDir := filepath.Join(f.root, fmt.Sprint(fixturePID))
	f.source.beforeFinalSample = func() { writeCheckpointFixtureStat(t, procDir, 123457) }
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted PID reuse during observation")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsChangedMainPID(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	call := 0
	f.source.mainPID = func(context.Context, string) (int, error) {
		call++
		if call == 1 {
			return fixturePID, nil
		}
		return fixturePID + 1, nil
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a changed systemd MainPID")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsExecutableMismatch(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.req.ExpectedExecutableSHA256 = strings.Repeat("0", 64)
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted an executable outside the allowlist")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsModelDigestMismatch(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.req.ExpectedModelSHA256 = strings.Repeat("0", 64)
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted model bytes outside the allowlist")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsModelChangedDuringObservation(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.source.beforeFinalSample = func() {
		changed := make([]byte, int(f.modelSize))
		for i := range changed {
			changed[i] = 'x'
		}
		if err := os.WriteFile(f.model, changed, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted an opened model changed after hashing and before final identity validation")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsModelSymlinkSwapDuringObservation(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.source.beforeFinalSample = func() {
		backup := f.model + ".opened"
		if err := os.Rename(f.model, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(backup, f.model); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a model path replaced by a symlink during observation")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsExecutableChangedDuringObservation(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.source.beforeFinalSample = func() {
		changed := make([]byte, int(f.exeSize))
		for i := range changed {
			changed[i] = 'x'
		}
		if err := os.WriteFile(f.exe, changed, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted an executable modified after hashing but before final identity validation")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsLoadedMappingChangedDuringObservation(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	f.source.beforeFinalSample = func() {
		mapsPath := filepath.Join(f.root, fmt.Sprint(fixturePID), "maps")
		if err := os.WriteFile(mapsPath, []byte("address perms offset dev inode pathname\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a listener process after its sampled GGUF mapping disappeared")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsSymlinkModelPath(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	link := filepath.Join(filepath.Dir(f.model), "alias.gguf")
	if err := os.Symlink(f.model, link); err != nil {
		t.Fatal(err)
	}
	f.req.ModelPath = link
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a symlinked model path")
	}
}

func TestCheckpointLocalIdentityLinuxObserverRejectsRemoteEndpointAndUnit(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	if _, _, _, err := parseCheckpointIdentityEndpoint("http://192.0.2.1:8080"); err == nil {
		t.Fatal("accepted remote endpoint")
	}
	f.req.ServiceUnit = "proxy.service"
	if _, err := observeCheckpointFixture(t, f); err == nil {
		t.Fatal("accepted a service unit outside the fixed allowlist")
	}
}

func TestCheckpointLocalIdentityLinuxProcReadersSeeRealListenerAndMapping(t *testing.T) {
	start, err := checkpointProcessStart(filepath.Join("/proc", fmt.Sprint(os.Getpid())), os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if start == 0 {
		t.Fatal("kernel process incarnation has no start ticks")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	matches, err := checkpointMatchingListeners(context.Background(), "/proc", net.ParseIP("127.0.0.1"), port)
	if err != nil || len(matches) != 1 {
		t.Fatalf("kernel listener reader returned %d listeners, err=%v", len(matches), err)
	}
	owned, err := checkpointProcessOwnsSocket(context.Background(), filepath.Join("/proc", fmt.Sprint(os.Getpid())), matches[0].inode)
	if err != nil || !owned {
		t.Fatalf("kernel fd reader did not bind listener to this process: owned=%v err=%v", owned, err)
	}

	file, err := os.CreateTemp(t.TempDir(), "mapped-model-*.gguf")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	data := []byte(strings.Repeat("mapped-gguf-", 4096))
	if _, err := file.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("real Linux file stat did not expose inode identity")
	}
	mapped, err := unix.Mmap(int(file.Fd()), 0, len(data), unix.PROT_READ, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Munmap(mapped)
	observedBytes, err := checkpointVerifyModelMapped(context.Background(), "/proc/self/maps", uint64(stat.Dev), stat.Ino, info.Size())
	if err != nil || observedBytes != info.Size() {
		t.Fatalf("kernel mapping reader did not observe complete mapped bytes: bytes=%d err=%v", observedBytes, err)
	}
}
