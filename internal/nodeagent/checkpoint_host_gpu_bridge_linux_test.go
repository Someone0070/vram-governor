//go:build linux

package nodeagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"vram-governor/internal/checkpointgpuobserver"
)

func TestCheckpointObserverSignedResponseRoleWrappers(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	namespace := checkpointgpuobserver.Namespace{Device: 4, Inode: 55, Filesystem: 0x6e736673, NamespaceType: 0x20000000}
	request := checkpointgpuobserver.Request{
		Version: checkpointgpuobserver.ProtocolVersion, Nonce: strings.Repeat("a", 64), InitPID: 1, InitStartTicks: 101,
		InitNamespaceDev: namespace.Device, InitNamespaceInode: namespace.Inode, InitNamespaceFS: namespace.Filesystem, InitNamespaceType: namespace.NamespaceType,
		WorkerPID: 37, WorkerStartTicks: 202, WorkerNamespaceDev: namespace.Device, WorkerNamespaceInode: namespace.Inode,
		WorkerNamespaceFS: namespace.Filesystem, WorkerNamespaceType: namespace.NamespaceType,
		GPUUUID: "GPU-00000000-0000-0000-0000-000000000001", GPUPCI: "0000:01:00.0",
	}
	requestBytes, err := checkpointgpuobserver.MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := sha256.Sum256(requestBytes)
	response := checkpointgpuobserver.Response{
		Version: checkpointgpuobserver.ProtocolVersion, RequestSHA256: hex.EncodeToString(requestDigest[:]), Nonce: request.Nonce,
		BootID: "00000000-0000-0000-0000-000000000002", Role: "node-agent", PeerUID: 1100,
		PeerExecutablePath: "/usr/sbin/vram-node-agent", PeerExecutableSHA256: strings.Repeat("c", 64),
		Peer: checkpointgpuobserver.Process{PID: 800, StartTicks: 303, NSpid: []int{800, 5}, Namespace: namespace, Cgroup: "/ct.slice/worker"},
		Init: checkpointgpuobserver.Process{PID: 900, StartTicks: request.InitStartTicks, NSpid: []int{900, 1}, Namespace: namespace, Cgroup: "/ct.slice/init"},
		Worker: checkpointgpuobserver.Process{PID: 937, StartTicks: request.WorkerStartTicks, NSpid: []int{937, request.WorkerPID}, Namespace: namespace, Cgroup: "/ct.slice/worker"},
		GPU: checkpointgpuobserver.GPUProcess{PID: 937, UUID: request.GPUUUID, Bytes: 1 << 20}, GPUUUID: request.GPUUUID, GPUPCI: request.GPUPCI,
		ObservedAtUnixNS: 10_000_000_000, ExpiresAtUnixNS: 12_000_000_000,
	}
	signForRole := func(role string, uid uint32) []byte {
		t.Helper()
		candidate := response
		candidate.Role, candidate.PeerUID = role, uid
		encoded, err := checkpointgpuobserver.SignResponse(candidate, private)
		if err != nil {
			t.Fatalf("sign %s positive response: %v", role, err)
		}
		return encoded
	}
	for _, test := range []struct{ role string; uid uint32 }{{"local-observer", 0}, {"fixed-supervisor", 0}, {"node-agent", 1100}} {
		encoded := signForRole(test.role, test.uid)
		if got, err := verifyCheckpointHostGPUResponseForRole(encoded, public, request, test.role, 11_000_000_000); err != nil || got.Role != test.role {
			t.Fatalf("signed %s response was not accepted by its dedicated role route: role=%q err=%v", test.role, got.Role, err)
		}
	}
	for _, test := range []struct{ signedRole, expectedRole string }{{"fixed-supervisor", "local-observer"}, {"local-observer", "fixed-supervisor"}, {"local-observer", "node-agent"}} {
		encoded := signForRole(test.signedRole, map[string]uint32{"node-agent": 1100}[test.signedRole])
		if _, err := verifyCheckpointHostGPUResponseForRole(encoded, public, request, test.expectedRole, 11_000_000_000); err == nil {
			t.Fatalf("signed %s response crossed the fixed %s wrapper", test.signedRole, test.expectedRole)
		}
	}
}

func TestCheckpointHostObserverFramingBoundsAndRoundTrip(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	body := bytes.Repeat([]byte("x"), 128)
	writeErr := make(chan error, 1)
	go func() { writeErr <- checkpointWriteFrame(left, body) }()
	got, err := checkpointReadFrame(right, checkpointgpuobserver.MaxRequestBytes)
	if err != nil || !bytes.Equal(got, body) {
		t.Fatalf("framed observer request did not round-trip: bytes=%d err=%v", len(got), err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	left.Close()
	right.Close()
	var noConnection net.Conn
	for _, invalid := range [][]byte{nil, bytes.Repeat([]byte("x"), checkpointgpuobserver.MaxRequestBytes+1)} {
		if err := checkpointWriteFrame(noConnection, invalid); err == nil {
			t.Fatal("invalid observer frame was accepted")
		}
	}
}

func TestCheckpointBridgeNamespaceTypeFromHeldCurrentPIDDescriptor(t *testing.T) {
	file, err := os.Open("/proc/self/ns/pid")
	if err != nil {
		t.Fatalf("open current PID namespace: %v", err)
	}
	defer file.Close()
	namespace, err := checkpointLocalNamespaceFromFD(int(file.Fd()))
	if err != nil {
		t.Fatalf("read held current PID namespace: %v", err)
	}
	if namespace.Filesystem != checkpointNSFSMagic || namespace.NamespaceType != uint64(unix.CLONE_NEWPID) || namespace.Inode == 0 {
		t.Fatalf("unexpected current PID namespace identity: %+v", namespace)
	}

	ordinary := filepath.Join(t.TempDir(), "not-a-namespace")
	if err := os.WriteFile(ordinary, []byte("ordinary file"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinaryFile, err := os.Open(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	defer ordinaryFile.Close()
	if _, err := checkpointLocalNamespaceFromFD(int(ordinaryFile.Fd())); err == nil {
		t.Fatal("ordinary file was accepted as a held namespace")
	}
}

type shortFrameWriter struct{}

func (shortFrameWriter) Write(raw []byte) (int, error) {
	if len(raw) == 0 {
		return 0, nil
	}
	return 1, nil
}

func TestCheckpointObserverFrameWriterHandlesShortWritesAndZeroProgress(t *testing.T) {
	if err := writeCheckpointFull(shortFrameWriter{}, []byte("bounded")); err != nil {
		t.Fatalf("short writer was not completed: %v", err)
	}
	if err := writeCheckpointFull(zeroProgressWriter{}, []byte("x")); err != io.ErrShortWrite {
		t.Fatalf("zero-progress writer returned %v", err)
	}
}

type zeroProgressWriter struct{}

func (zeroProgressWriter) Write([]byte) (int, error) { return 0, nil }

func TestCheckpointObserverTrustPinDetectsContentAndPathSubstitution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pin")
	if err := os.WriteFile(path, []byte("approved"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	pin := &checkpointNodeTrustPin{file: file, path: path, device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), mode: info.Mode(), uid: stat.Uid, gid: stat.Gid, links: uint64(stat.Nlink), mtime: stat.Mtim, ctime: stat.Ctim, bytes: []byte("approved")}
	if err := pin.recheck(); err != nil {
		t.Fatalf("stable held pin rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("substitute"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pin.recheck(); err == nil {
		t.Fatal("mutated root trust bytes were accepted")
	}
	stable := filepath.Join(dir, "stable")
	if err := os.WriteFile(stable, []byte("approved"), 0600); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(stable)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	heldInfo, err := held.Stat()
	if err != nil {
		t.Fatal(err)
	}
	heldStat := heldInfo.Sys().(*syscall.Stat_t)
	pathPin := &checkpointNodeTrustPin{file: held, path: stable, device: uint64(heldStat.Dev), inode: heldStat.Ino, size: heldInfo.Size(), mode: heldInfo.Mode(), uid: heldStat.Uid, gid: heldStat.Gid, links: uint64(heldStat.Nlink), mtime: heldStat.Mtim, ctime: heldStat.Ctim, bytes: []byte("approved")}
	replacement := filepath.Join(dir, "replacement")
	if err := os.Rename(stable, replacement); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stable, []byte("approved"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pathPin.recheck(); err == nil {
		t.Fatal("same-content trust path replacement was accepted")
	}
}

func TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation(t *testing.T) {
	ns := checkpointgpuobserver.Namespace{Device: 7, Inode: 19, Filesystem: checkpointNSFSMagic, NamespaceType: uint64(unix.CLONE_NEWPID)}
	self := &checkpointHeldLocalProcess{pid: 22, start: 101, uid: 65534, exe: "/usr/sbin/vram-node-agent", exeSHA256: strings.Repeat("a", 64), namespace: ns}
	response := checkpointgpuobserver.Response{BootID: "00000000-0000-0000-0000-000000000001", Role: "node-agent", PeerUID: self.uid, PeerExecutablePath: self.exe, PeerExecutableSHA256: self.exeSHA256, Peer: checkpointgpuobserver.Process{NSpid: []int{700, 22}, StartTicks: self.start, Namespace: ns}}
	if err := validateCheckpointObserverLocalPeerJoin(response, self, 22, response.BootID); err != nil {
		t.Fatalf("valid current nested peer rejected: %v", err)
	}
	if checkpointHostGPUExpectedRole(65534) != "node-agent" || checkpointHostGPUExpectedRole(0) != "fixed-supervisor" {
		t.Fatal("legacy host routes no longer select their fixed role from the held caller privilege")
	}
	for _, role := range []string{"node-agent", "fixed-supervisor", "local-observer"} {
		if err := validateCheckpointHostGPUResponseRole(role, role); err != nil {
			t.Fatalf("exact expected role %q rejected: %v", role, err)
		}
	}
	for _, pair := range [][2]string{{"fixed-supervisor", "local-observer"}, {"node-agent", "local-observer"}, {"unknown", "local-observer"}} {
		if err := validateCheckpointHostGPUResponseRole(pair[0], pair[1]); err == nil {
			t.Fatalf("signed role %q was accepted for fixed route %q", pair[0], pair[1])
		}
	}
	controls := map[string]func(*checkpointgpuobserver.Response){
		"namespace":   func(r *checkpointgpuobserver.Response) { r.Peer.Namespace.Inode++ },
		"peer PID":    func(r *checkpointgpuobserver.Response) { r.Peer.NSpid[len(r.Peer.NSpid)-1]++ },
		"start ticks": func(r *checkpointgpuobserver.Response) { r.Peer.StartTicks++ },
		"boot ID":     func(r *checkpointgpuobserver.Response) { r.BootID = "00000000-0000-0000-0000-000000000002" },
		"UID":         func(r *checkpointgpuobserver.Response) { r.PeerUID++ },
		"executable":  func(r *checkpointgpuobserver.Response) { r.PeerExecutableSHA256 = strings.Repeat("b", 64) },
	}
	for name, mutate := range controls {
		t.Run(name, func(t *testing.T) {
			changed := response
			changed.Peer = response.Peer
			changed.Peer.NSpid = append([]int(nil), response.Peer.NSpid...)
			mutate(&changed)
			if err := validateCheckpointObserverLocalPeerJoin(changed, self, 22, response.BootID); err == nil {
				t.Fatal("signed peer substitution was accepted")
			}
		})
	}
}
