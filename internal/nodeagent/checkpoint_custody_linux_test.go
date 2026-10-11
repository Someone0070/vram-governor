//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestCheckpointCustodyLinuxRejectsUnknownPID(t *testing.T) {
	if _, err := checkpointProcessStart("/proc/999999999", 999999999); err == nil {
		t.Fatal("unknown PID produced a process incarnation")
	}
}

func TestCheckpointCustodyLinuxRejectsUnsupportedFilesystem(t *testing.T) {
	fixture, err := os.CreateTemp(t.TempDir(), "verity-argument-")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	arg, err := checkpointVerityEnableArgument(int(fixture.Fd()))
	if err != nil {
		t.Fatalf("build fs-verity enable argument: %v", err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(fixture.Fd()), &fs); err != nil {
		t.Fatal(err)
	}
	blockSize := uint64(os.Getpagesize())
	if uint64(fs.Bsize) < blockSize {
		blockSize = uint64(fs.Bsize)
	}
	if got := *(*uint32)(unsafe.Pointer(&arg[0])); got != 1 {
		t.Fatalf("unexpected fs-verity argument version: %d", got)
	}
	if got := *(*uint32)(unsafe.Pointer(&arg[4])); got != custodyVeritySHA256 {
		t.Fatalf("unexpected fs-verity hash algorithm: %d", got)
	}
	if got := *(*uint32)(unsafe.Pointer(&arg[8])); uint64(got) != blockSize || got < 1024 || got&(got-1) != 0 {
		t.Fatalf("fs-verity block size argument was not filesystem/page compatible: got=%d expected=%d", got, blockSize)
	}
	f, err := os.Open("/proc/self/cmdline")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = enableAndMeasureVerity(int(f.Fd())); err == nil {
		t.Fatal("procfs unexpectedly yielded immutable-source proof")
	}
}

func TestCheckpointCustodyLinuxVerifyBoundsManyValidReceipts(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: root, MaxArtifactBytes: 1 << 20, MaxStagingBytes: 2 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := loadCustodyKey(store)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile(checkpointCustodyBootIDPath())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 20; i++ {
		nonce := fmt.Sprintf("%064x", i)
		receipt := custodyReceipt{
			Version: 1, KeyID: custodyKeyID(pub), Nonce: nonce, BootID: strings.TrimSpace(string(boot)), Endpoint: "http://127.0.0.1:9",
			PrelaunchBootNS: 1, StartBootNS: 1, StartedBootNS: 1, PID: 900_000_000 + i, StartTicks: 1,
			ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified",
			ActualAlias: strings.Repeat("x", 900_000),
		}
		payload, marshalErr := custodyReceiptBytes(receipt)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		signed := custodySignedReceipt{Receipt: receipt, Signature: hex.EncodeToString(ed25519.Sign(priv, payload))}
		raw, marshalErr := json.Marshal(signed)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if len(raw) > custodyMaxReceiptBytes {
			t.Fatalf("test receipt exceeds per-file bound: %d", len(raw))
		}
		if err = os.WriteFile(custodyReceiptPath(store.root, nonce), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	readNames := make([]string, 0, 2)
	ctx, cancel := context.WithCancel(context.Background())
	store.verifyTestAfterReceiptRead = func(name string) {
		readNames = append(readNames, name)
		if len(readNames) == 2 {
			cancel()
		}
	}
	if _, _, err = store.VerifyBinding(ctx, "http://127.0.0.1:9", checkpointIdentityServiceUnit); !errors.Is(err, context.Canceled) || len(readNames) != 2 || readNames[0] == readNames[1] {
		t.Fatalf("receipt verification did not honor real cancellation after distinct receipts: reads=%v err=%v", readNames, err)
	}
	cancel()
	readNames = readNames[:0]
	deadlineCtx, deadlineCancel := context.WithTimeout(context.Background(), time.Second)
	defer deadlineCancel()
	store.verifyTestAfterReceiptRead = func(name string) {
		readNames = append(readNames, name)
		if len(readNames) == 2 {
			<-deadlineCtx.Done()
		}
	}
	if _, _, err = store.VerifyBinding(deadlineCtx, "http://127.0.0.1:9", checkpointIdentityServiceUnit); !errors.Is(err, context.DeadlineExceeded) || len(readNames) != 2 || readNames[0] == readNames[1] {
		t.Fatalf("receipt verification did not honor deadline after distinct receipts: reads=%v err=%v", readNames, err)
	}
	store.verifyTestAfterReceiptRead = nil
	_, valid, err := store.VerifyBinding(context.Background(), "http://127.0.0.1:9", checkpointIdentityServiceUnit)
	if err == nil || valid || !strings.Contains(err.Error(), "aggregate verification-work budget") {
		t.Fatal("custody rejection assertion: aggregate receipt verification-work budget was not enforced")
	}
}

func TestCheckpointCustodyLinuxVerifyRejectsReceiptFIFOWithoutBlocking(t *testing.T) {
	root := filepath.Join(t.TempDir(), "store")
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: root, MaxArtifactBytes: 1 << 20, MaxStagingBytes: 2 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fifo := custodyReceiptPath(store.root, strings.Repeat("a", 64))
	if err = unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, valid, err := store.VerifyBinding(ctx, "http://127.0.0.1:9", checkpointIdentityServiceUnit)
	if err == nil || valid || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("custody rejection assertion: non-regular receipt path blocked or verified")
	}
}

func TestCheckpointCustodyLinuxArtifactOpenRejectsFIFOWithoutBlocking(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "artifact.gguf")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := openCheckpointCustodyArtifact(fifo)
	if f != nil {
		f.Close()
	}
	if err == nil {
		t.Fatal("custody rejection assertion: non-regular artifact passed source fd check")
	}
}

func TestCheckpointCustodyLinuxPrepareAndStageExecutableRejectFIFOs(t *testing.T) {
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(t.TempDir(), "store"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 4 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	modelFIFO := filepath.Join(t.TempDir(), "source.gguf")
	if err = unix.Mkfifo(modelFIFO, 0600); err != nil {
		t.Fatal(err)
	}
	prepare := make(chan error, 1)
	go func() {
		_, e := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelFIFO, ApprovedSHA256: strings.Repeat("a", 64), ExpectedBytes: 1024})
		prepare <- e
	}()
	select {
	case err = <-prepare:
		if err == nil {
			t.Fatal("custody rejection assertion: FIFO model source was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("custody rejection assertion: Prepare blocked opening FIFO source")
	}

	exeFIFO := filepath.Join(t.TempDir(), "launcher")
	if err = unix.Mkfifo(exeFIFO, 0500); err != nil {
		t.Fatal(err)
	}
	stage := make(chan error, 1)
	go func() {
		_, fd, e := custodyStageExecutable(context.Background(), store, exeFIFO, strings.Repeat("a", 64))
		if fd != nil {
			fd.Close()
		}
		stage <- e
	}()
	select {
	case err = <-stage:
		if err == nil {
			t.Fatal("custody rejection assertion: FIFO executable source was accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("custody rejection assertion: executable staging blocked opening FIFO")
	}
}

func TestCheckpointCustodyLinuxStageValidatorsRejectFIFOPathReplacement(t *testing.T) {
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(t.TempDir(), "store"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 4 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(t.TempDir(), "replacement")
	if err = unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if err = validatePreparedCheckpointPlatform(&CheckpointPreparedModel{store: store, path: fifo}, nil); err == nil {
		t.Fatal("custody rejection assertion: model validator blocked on or accepted FIFO replacement")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	held, err := openCheckpointCustodyArtifact(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = validateCheckpointLaunchExecutablePlatform(fifo, strings.Repeat("a", 64), held); err == nil {
		t.Fatal("custody rejection assertion: executable validator blocked on or accepted FIFO replacement")
	}
}

func TestCheckpointCustodyLinuxVerifyBoundsLiveCandidates(t *testing.T) {
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(t.TempDir(), "store"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 2 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := loadCustodyKey(store)
	if err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile(checkpointCustodyBootIDPath())
	if err != nil {
		t.Fatal(err)
	}
	pid := os.Getpid()
	startTicks, err := checkpointProcessStart("/proc/self", pid)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://127.0.0.1:9"
	for i := 1; i <= custodyMaxLiveVerifyCandidates+1; i++ {
		nonce := fmt.Sprintf("%064x", i)
		r := custodyReceipt{
			Version: 1, KeyID: custodyKeyID(pub), Nonce: nonce, BootID: strings.TrimSpace(string(boot)),
			PrelaunchBootNS: 1, StartBootNS: 1, StartedBootNS: 1,
			PID: pid, StartTicks: startTicks, ServiceUnit: checkpointIdentityServiceUnit,
			UnitAssociation: "label-only-unverified", Endpoint: endpoint,
		}
		b, marshalErr := custodyReceiptBytes(r)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		raw, marshalErr := json.Marshal(custodySignedReceipt{Receipt: r, Signature: hex.EncodeToString(ed25519.Sign(priv, b))})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if err = os.WriteFile(custodyReceiptPath(store.root, nonce), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, valid, err := store.VerifyBinding(context.Background(), endpoint, checkpointIdentityServiceUnit)
	if err == nil || valid || !strings.Contains(err.Error(), "live-process candidate verification budget") {
		t.Fatal("custody rejection assertion: authenticated live-process candidate budget was not enforced")
	}
}

func TestCheckpointCustodyLinuxFlockHonorsContext(t *testing.T) {
	base := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if base == "" {
		t.Skip("isolated custody filesystem not requested")
	}
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "flock-test"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 4 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(filepath.Join(store.root, "custody.lock"), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err = lockCustodyProcess(ctx, store); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cross-process lock ignored acquisition deadline: %v", err)
	}
	if err = unix.Flock(fd, unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointCustodyClockAuthorityUsesBootTimeAndBootIDOnly(t *testing.T) {
	if checkpointCustodyClockID() != unix.CLOCK_BOOTTIME || checkpointCustodyBootIDPath() != "/proc/sys/kernel/random/boot_id" {
		t.Fatal("custody rejection assertion: clock authority must exclusively use CLOCK_BOOTTIME and kernel boot ID")
	}
	first, err := checkpointBootTimeNS()
	if err != nil || first <= 0 {
		t.Fatalf("custody rejection assertion: CLOCK_BOOTTIME measurement unavailable: %v", err)
	}
	second, err := checkpointBootTimeNS()
	if err != nil || second < first {
		t.Fatalf("custody rejection assertion: monotonic boot-clock bracket moved backwards: first=%d second=%d err=%v", first, second, err)
	}
	bootID, err := checkpointReadBounded(checkpointCustodyBootIDPath(), 128)
	if err != nil || strings.TrimSpace(string(bootID)) == "" {
		t.Fatalf("custody rejection assertion: kernel boot identity is unavailable: %v", err)
	}
}

func TestCheckpointCustodyLinuxFSVerityKernelProof(t *testing.T) {
	path := os.Getenv("CHECKPOINT_CUSTODY_VERITY_FILE")
	if path == "" {
		t.Skip("kernel provisioning not requested")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := enableAndMeasureVerity(int(f.Fd())); err != nil {
		t.Fatalf("failed to enable fs-verity on the disposable kernel fixture: %v", err)
	}
	got, err := measureVerity(int(f.Fd()))
	if err != nil {
		t.Fatalf("real fs-verity measurement failed: %v", err)
	}
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ordinary := sha256.Sum256(bytes)
	if got == hex.EncodeToString(ordinary[:]) {
		t.Fatal("verity Merkle digest was confused with ordinary SHA-256")
	}
}

func TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering(t *testing.T) {
	base := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if base == "" {
		t.Skip("kernel provisioning not requested")
	}
	base = filepath.Join(base, "managed-e2e")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	modelPath := filepath.Join(base, "source.gguf")
	payload := bytes.Repeat([]byte("small allowlisted model fixture\n"), 512)
	if err := os.WriteFile(modelPath, payload, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	sourceSHA := hex.EncodeToString(digest[:])
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(base, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 128 << 20, ReserveBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatalf("prepare fs-verity source: %v", err)
	}
	link := filepath.Join(base, "source-link.gguf")
	if err = os.Symlink(modelPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Prepare(context.Background(), CheckpointCustodySource{Path: link, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))}); err == nil {
		t.Fatal("symlinked source path passed immutable preparation")
	}
	limited := &CheckpointCustodyStore{root: store.root, maxBytes: store.maxBytes, maxStagingBytes: int64(len(payload)) + store.reserve, reserve: store.reserve, rootDevice: store.rootDevice, rootInode: store.rootInode, modelsDevice: store.modelsDevice, modelsInode: store.modelsInode, launchersDevice: store.launchersDevice, launchersInode: store.launchersInode, receiptsDevice: store.receiptsDevice, receiptsInode: store.receiptsInode}
	if _, err = limited.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))}); err == nil {
		t.Fatal("staging bytes plus reserve exceeded the explicit disk quota")
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	endpoint := "http://" + addr
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exeBytes, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	exeSum := sha256.Sum256(exeBytes)
	launchExe := filepath.Join(base, "controlled-executable")
	if err = os.WriteFile(launchExe, exeBytes, 0500); err != nil {
		t.Fatal(err)
	}
	raceExe := filepath.Join(base, "race-executable")
	if err = os.WriteFile(raceExe, exeBytes, 0500); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(raceExe, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launchReq := CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "controlled-fixture", ExpectedExecutableSHA256: hex.EncodeToString(exeSum[:])}
	racePrepared, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	launch, err := store.Begin(racePrepared, launchReq)
	if err != nil {
		t.Fatal(err)
	}
	started := false
	defer func() {
		if !started {
			_ = launch.Abort()
		}
	}()
	duplicate, duplicateErr := store.Begin(racePrepared, launchReq)
	if duplicateErr == nil {
		if duplicate != nil {
			_ = duplicate.Abort()
		}
		t.Fatal("custody rejection assertion: reused prepared source gained a second launch permit")
	}
	if duplicateErr.Error() != "prepared source has already been used" {
		if duplicate != nil {
			_ = duplicate.Abort()
		}
		t.Fatalf("custody rejection assertion: reused prepared source was not rejected by single-use validation: got %v", duplicateErr)
	}
	if duplicate != nil {
		_ = duplicate.Abort()
	}
	launchExeMoved := launch.executablePath + ".moved"
	if err = os.Rename(launch.executablePath, launchExeMoved); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(launch.executablePath, []byte("replacement executable bytes"), 0500); err != nil {
		t.Fatal(err)
	}
	startErr := launch.Start()
	if removeErr := os.Remove(launch.executablePath); removeErr != nil {
		t.Fatal(removeErr)
	}
	if err = os.Rename(launchExeMoved, launch.executablePath); err != nil {
		t.Fatal(err)
	}
	if startErr == nil {
		started = true
		_ = stopCustodyTestChild(launch)
		t.Fatal("custody rejection assertion: replaced executable pathname launched despite pinned inode mismatch")
	}
	if err = os.Remove(launch.executablePath); err != nil {
		t.Fatal(err)
	}
	if err = launch.Abort(); err != nil {
		t.Fatal(err)
	}
	prepared, err = store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	probe, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = probe.Addr().String()
	probe.Close()
	endpoint = "http://" + addr
	cmd = exec.Command(launchExe, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launch, err = store.Begin(prepared, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "controlled-fixture", ExpectedExecutableSHA256: hex.EncodeToString(exeSum[:])})
	if err != nil {
		t.Fatal(err)
	}
	started = false
	defer func() {
		if !started {
			_ = launch.Abort()
		}
	}()
	if err = launch.Start(); err != nil {
		t.Fatalf("start controlled child: %v", err)
	}
	started = true
	waited := false
	defer func() {
		if !waited {
			_ = stopCustodyTestChild(launch)
		}
	}()
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		_ = stopCustodyTestChild(launch)
		t.Fatal("controlled child did not bind its endpoint")
	}
	if err = launch.Commit(context.Background()); err != nil {
		_ = stopCustodyTestChild(launch)
		t.Fatalf("commit authentic controlled launch: %v", err)
	}
	binding, valid, err := store.VerifyBinding(context.Background(), endpoint, checkpointIdentityServiceUnit)
	if err != nil || !valid {
		t.Fatalf("valid local custody receipt rejected: valid=%v err=%v", valid, err)
	}
	if binding.BindingSHA256 == "" || binding.ArtifactSHA256 != sourceSHA || binding.ActualAlias != "controlled-fixture" || binding.UnitAssociation != "label-only-unverified" {
		t.Fatal("verified custody binding omitted source, alias, or explicit unit-association status")
	}
	receiptPath := custodyReceiptPath(store.root, launch.nonce)
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var signed custodySignedReceipt
	if err = json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	validSigned := signed
	pub, priv, err := loadCustodyKey(store)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Receipt.KeyID != custodyKeyID(pub) || signed.Receipt.UnitAssociation != "label-only-unverified" || signed.Receipt.StartBootNS < signed.Receipt.PrelaunchBootNS || signed.Receipt.StartedBootNS < signed.Receipt.StartBootNS {
		t.Fatal("receipt omitted local key pin, explicit unit boundary, or monotonic launch bracket")
	}
	// A replacement pathname cannot inherit the receipt for the mapped inode.
	moved := prepared.path + ".moved"
	if err = os.Rename(prepared.path, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(prepared.path, []byte("replacement bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("replacement source inode inherited verified custody")
	}
	if err = os.Remove(prepared.path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(moved, prepared.path); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); !ok {
		t.Fatal("restored original verity inode did not recover live verification")
	}
	// A controller-style forged signature and an authentic signature attached
	// to an unknown PID both fail closed.
	forged := signed
	forged.Signature = strings.Repeat("00", ed25519.SignatureSize)
	writeCustodyReceiptForTest(t, receiptPath, forged)
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("custody rejection assertion: forged receipt verified")
	}
	mixedLegacy := validSigned
	mixedLegacy.Receipt.Executable = &custodySourceIdentity{CanonicalPath: launch.executablePath, SHA256: launch.expectedExecutableSHA256}
	mixedLegacy.Signature = hex.EncodeToString(ed25519.Sign(priv, mustReceiptBytesForTest(t, mixedLegacy.Receipt)))
	writeCustodyReceiptForTest(t, receiptPath, mixedLegacy)
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("legacy v1 receipt with a controlled executable field was accepted")
	}
	signed.Receipt.PID = 999999999
	signed.Signature = hex.EncodeToString(ed25519.Sign(priv, mustReceiptBytesForTest(t, signed.Receipt)))
	writeCustodyReceiptForTest(t, receiptPath, signed)
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("signed receipt with unknown process verified")
	}
	badBracket := validSigned
	badBracket.Receipt.StartBootNS = 0
	badBracket.Signature = hex.EncodeToString(ed25519.Sign(priv, mustReceiptBytesForTest(t, badBracket.Receipt)))
	writeCustodyReceiptForTest(t, receiptPath, badBracket)
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("invalid monotonic launch bracket verified")
	}
	if err = os.WriteFile(receiptPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	replay := filepath.Join(store.root, "receipts", "replayed.json")
	if err = os.Remove(receiptPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(replay, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("receipt replay under another filename verified")
	}
	_ = os.Remove(replay)
	if err = os.WriteFile(receiptPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = stopCustodyTestChild(launch); err == nil {
		t.Fatal("controlled child unexpectedly exited successfully")
	}
	waited = true
	if ok, _ := store.Verify(context.Background(), endpoint, checkpointIdentityServiceUnit); ok {
		t.Fatal("receipt survived its process exit")
	}
	testModelDescriptorSurvivesPathReplacement(t, store, base, modelPath, sourceSHA, int64(len(payload)), exe, exeSum)
	testCommitCancellationDuringObservation(t, store, base, modelPath, sourceSHA, int64(len(payload)), exe, exeSum)
	// A launched but uncommitted child has no receipt, including after it crashes.
	second, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	probe, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr = probe.Addr().String()
	probe.Close()
	endpoint = "http://" + addr
	cmd = exec.Command(exe, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr, "CHECKPOINT_CUSTODY_PARTIAL_MAPPING=1")
	launch2, err := store.Begin(second, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "controlled-fixture", ExpectedExecutableSHA256: hex.EncodeToString(exeSum[:])})
	if err != nil {
		t.Fatal(err)
	}
	if err = launch2.Start(); err != nil {
		t.Fatal(err)
	}
	secondWaited := false
	defer func() {
		if !secondWaited {
			_ = stopCustodyTestChild(launch2)
		}
	}()
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		_ = stopCustodyTestChild(launch2)
		secondWaited = true
		t.Fatal("partial-mapping child did not bind")
	}
	if err = launch2.Commit(context.Background()); err == nil {
		_ = stopCustodyTestChild(launch2)
		secondWaited = true
		t.Fatal("partial model mapping gained a custody receipt")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = launch2.WaitContext(ctx)
	cancel()
	secondWaited = true
	if err == nil {
		t.Fatal("pending test child unexpectedly exited successfully")
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "receipts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("uncommitted/crashed child wrote a receipt: count=%d err=%v", len(entries), err)
	}
}

func TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping(t *testing.T) {
	base := os.Getenv("CHECKPOINT_CUSTODY_TEST_DIR")
	if base == "" {
		t.Skip("kernel provisioning not requested")
	}
	for _, scenario := range []struct {
		name                                                                                         string
		partial, fifo, closed, swapped, wrongArgv, closeListener, public, terminal, tamperedTerminal bool
	}{{name: "unmapped"}, {name: "partial", partial: true}, {name: "fifo", fifo: true}, {name: "closed-fd", closed: true}, {name: "swapped-fd", swapped: true}, {name: "wrong-argv", wrongArgv: true}, {name: "listener-drift", closeListener: true}, {name: "public-v1", public: true}, {name: "terminal-release", terminal: true}, {name: "terminal-tampered-executable", terminal: true, tamperedTerminal: true}} {
		name := scenario.name
		t.Run(name, func(t *testing.T) {
			root, err := os.MkdirTemp(base, "controlled-source-"+name+"-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			modelPath := filepath.Join(root, "source.gguf")
			payload := bytes.Repeat([]byte("controlled immutable source fixture\n"), 128)
			if err = os.WriteFile(modelPath, payload, 0600); err != nil {
				t.Fatal(err)
			}
			sourceHash := sha256.Sum256(payload)
			sourceSHA := hex.EncodeToString(sourceHash[:])
			store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: filepath.Join(root, "custody"), MaxArtifactBytes: 1 << 20, MaxStagingBytes: 128 << 20, ReserveBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: int64(len(payload))})
			if err != nil {
				t.Fatalf("prepare verity-backed source: %v", err)
			}
			probe, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			addr := probe.Addr().String()
			_ = probe.Close()
			_, portText, splitErr := net.SplitHostPort(addr)
			portValue, portErr := strconv.ParseUint(portText, 10, 16)
			if splitErr != nil || portErr != nil {
				t.Fatalf("parse controlled fixture listener address: %v %v", splitErr, portErr)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			executableBytes, err := os.ReadFile(executable)
			if err != nil {
				t.Fatal(err)
			}
			executableSHA := sha256.Sum256(executableBytes)
			runPath := filepath.Join(root, "controlled-child")
			if err = os.WriteFile(runPath, executableBytes, 0500); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(runPath, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			env := []string{"CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CONTROLLED_SOURCE_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT=" + addr}
			if scenario.closed {
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_CLOSE_FD=1")
			}
			if scenario.swapped {
				swapPath := filepath.Join(root, "replacement.gguf")
				if err = os.WriteFile(swapPath, bytes.Repeat([]byte("replacement source"), 32), 0600); err != nil {
					t.Fatal(err)
				}
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_SWAP_PATH="+swapPath)
			}
			if scenario.wrongArgv {
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_WRONG_ARGV=1")
			}
			closeListenerMarker := filepath.Join(root, "close-listener")
			if scenario.closeListener {
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_CLOSE_LISTENER="+closeListenerMarker)
			}
			if scenario.partial {
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_PARTIAL_MAP=1")
			}
			if scenario.fifo {
				fifoPath := filepath.Join(root, "descriptor.fifo")
				if err = unix.Mkfifo(fifoPath, 0600); err != nil {
					t.Fatal(err)
				}
				env = append(env, "CHECKPOINT_CONTROLLED_SOURCE_FIFO="+fifoPath)
			}
			cmd.Env = append(os.Environ(), env...)
			launchRequest := CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "controlled-source-fixture", ExpectedExecutableSHA256: hex.EncodeToString(executableSHA[:])}
			var launch *CheckpointControlledLaunch
			if scenario.public {
				launch, err = store.BeginContext(context.Background(), prepared, launchRequest)
			} else {
				launch, err = store.beginFixedContext(context.Background(), prepared, launchRequest)
			}
			if err != nil {
				t.Fatal(err)
			}
			started := false
			defer func() {
				if started {
					_ = stopCustodyTestChild(launch)
				} else {
					_ = launch.Abort()
				}
			}()
			if err = launch.Start(); err != nil {
				t.Fatal(err)
			}
			started = true
			if !waitForCustodyEndpoint(addr, 5*time.Second) {
				t.Fatal("controlled child did not own its listener")
			}
			if scenario.closeListener {
				if err = os.WriteFile(closeListenerMarker, []byte("close"), 0600); err != nil {
					t.Fatal(err)
				}
				time.Sleep(100 * time.Millisecond)
			}
			if scenario.closed || scenario.swapped || scenario.wrongArgv || scenario.closeListener || scenario.public {
				commitErr := launch.Commit(context.Background())
				if commitErr == nil {
					t.Fatal("controlled custody accepted a closed/substituted descriptor, wrong argv, listener drift, or public v1 promotion")
				}
				if scenario.public {
					if _, found, verifyErr := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit); verifyErr != nil || found {
						t.Fatalf("public v1 launch was promoted after controlled commit rejection: found=%v err=%v", found, verifyErr)
					}
				}
				return
			}
			if scenario.fifo {
				commitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				commitDone := make(chan error, 1)
				go func() { commitDone <- launch.Commit(commitCtx) }()
				select {
				case commitErr := <-commitDone:
					cancel()
					if commitErr == nil {
						t.Fatal("controlled source commit accepted a FIFO substituted for descriptor four")
					}
				case <-commitCtx.Done():
					cancel()
					t.Fatal("controlled source FIFO descriptor rejection exceeded its bound")
				}
				return
			}
			if err = launch.Commit(context.Background()); err != nil {
				t.Fatalf("controlled source commit rejected an unmapped/partially mapped child: %v", err)
			}
			binding, ok, err := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit)
			if err != nil || !ok || binding.EvidenceKind != "controlled-source-fs-verity-v2" || binding.ModelArgument != "/proc/self/fd/4" || binding.ArgvSHA256 == "" {
				t.Fatalf("signed controlled source binding missing: ok=%v binding=%+v err=%v", ok, binding, err)
			}
			receiptPath := custodyReceiptPath(store.root, binding.Nonce)
			originalReceipt, err := os.ReadFile(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			for name, altered := range map[string][]byte{
				"signature-tamper": func() []byte {
					var signed custodySignedReceipt
					if json.Unmarshal(originalReceipt, &signed) != nil {
						t.Fatal("decode signed fixture receipt")
					}
					signed.Signature = strings.Repeat("0", len(signed.Signature))
					raw, _ := json.Marshal(signed)
					return raw
				}(),
				"downgrade": bytes.Replace(originalReceipt, []byte(`"version":2`), []byte(`"version":1`), 1),
			} {
				if err = os.WriteFile(receiptPath, altered, 0600); err != nil {
					t.Fatal(err)
				}
				if _, tamperedOK, verifyErr := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit); verifyErr != nil || tamperedOK {
					_ = os.WriteFile(receiptPath, originalReceipt, 0600)
					t.Fatalf("controlled receipt %s was accepted: ok=%v err=%v", name, tamperedOK, verifyErr)
				}
				if err = os.WriteFile(receiptPath, originalReceipt, 0600); err != nil {
					t.Fatal(err)
				}
			}
			pub, private, keyErr := loadCustodyKey(store)
			var signedOriginal custodySignedReceipt
			if err = json.Unmarshal(originalReceipt, &signedOriginal); err != nil || signedOriginal.Receipt.Executable == nil {
				t.Fatalf("decode controlled fixture receipt: %v", err)
			}
			if keyErr != nil || custodyKeyID(pub) != signedOriginal.Receipt.KeyID {
				t.Fatalf("load controlled fixture receipt key: %v", keyErr)
			}
			mutations := map[string]func(*custodyReceipt){
				"source-inode":     func(r *custodyReceipt) { r.Source.Inode++ },
				"source-verity":    func(r *custodyReceipt) { r.Source.VerityDigest = strings.Repeat("0", len(r.Source.VerityDigest)) },
				"executable-inode": func(r *custodyReceipt) { r.Executable.Inode++ },
				"executable-verity": func(r *custodyReceipt) {
					r.Executable.VerityDigest = strings.Repeat("0", len(r.Executable.VerityDigest))
				},
				"argv":        func(r *custodyReceipt) { r.ArgvSHA256 = strings.Repeat("0", len(r.ArgvSHA256)) },
				"start-ticks": func(r *custodyReceipt) { r.StartTicks++ },
				"listener":    func(r *custodyReceipt) { r.SocketInode++ },
				"unknown-pid": func(r *custodyReceipt) { r.PID = 999999999 },
			}
			if scenario.name == "unmapped" {
				for mutationName, mutate := range mutations {
					t.Run("receipt-"+mutationName, func(t *testing.T) {
						altered := signedOriginal.Receipt
						executableCopy := *signedOriginal.Receipt.Executable
						altered.Executable = &executableCopy
						mutate(&altered)
						canonical, canonicalErr := custodyReceiptBytes(altered)
						if canonicalErr != nil {
							t.Fatal(canonicalErr)
						}
						alteredSigned, marshalErr := json.Marshal(custodySignedReceipt{Receipt: altered, Signature: hex.EncodeToString(ed25519.Sign(private, canonical))})
						if marshalErr != nil {
							t.Fatal(marshalErr)
						}
						if writeErr := os.WriteFile(receiptPath, alteredSigned, 0600); writeErr != nil {
							t.Fatal(writeErr)
						}
						_, accepted, verifyErr := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit)
						if writeErr := os.WriteFile(receiptPath, originalReceipt, 0600); writeErr != nil {
							t.Fatal(writeErr)
						}
						if verifyErr != nil || accepted {
							t.Fatalf("controlled verifier accepted mutated %s receipt: found=%v err=%v", mutationName, accepted, verifyErr)
						}
						if _, accepted, verifyErr = store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit); verifyErr != nil || !accepted {
							t.Fatalf("restored controlled receipt failed its positive verification after %s: found=%v err=%v", mutationName, accepted, verifyErr)
						}
					})
				}
			}
			identityReq := CheckpointIdentityRequest{Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ModelPath: prepared.path, ExpectedModelSHA256: sourceSHA, ApprovedModelRoots: []string{filepath.Dir(prepared.path)}, ExpectedExecutableSHA256: hex.EncodeToString(executableSHA[:])}
			identitySource := checkpointLinuxSource{procRoot: "/proc", mainPID: func(context.Context, string) (int, error) { return launch.cmd.Process.Pid, nil }}
			if _, err = observeCheckpointIdentityLinux(context.Background(), identityReq, "http://"+addr, net.ParseIP("127.0.0.1"), uint16(portValue), identitySource); err == nil {
				t.Fatal("generic full-mapping identity observer accepted the same unmapped/partial child")
			}
			identity, err := observeCheckpointIdentityControlledLinux(context.Background(), identityReq, "http://"+addr, net.ParseIP("127.0.0.1"), uint16(portValue), identitySource, binding)
			mappingWrong := (!scenario.partial && identity.ObservedMappedBytes != 0) || (scenario.partial && (identity.ObservedMappedBytes <= 0 || identity.ObservedMappedBytes >= identity.ModelSize))
			if err != nil || mappingWrong || identity.EvidenceKind != binding.EvidenceKind {
				t.Fatalf("controlled local identity failed or overstated mapping evidence: %+v err=%v", identity, err)
			}
			if scenario.name == "unmapped" {
				// These synthetic unit samples exercise the real custody→local
				// observer→join path without claiming live systemd association evidence.
				makeUnitSource := func(changeSecond bool) checkpointUnitLinuxSource {
					invocation := "0123456789abcdef0123456789abcdef"
					calls := 0
					return checkpointUnitLinuxSource{
						procRoot: "/proc",
						collect: func(callCtx context.Context, expectedPID int) (checkpointUnitObservation, error) {
							calls++
							if err := callCtx.Err(); err != nil {
								return checkpointUnitObservation{}, err
							}
							if expectedPID != 0 && expectedPID != launch.cmd.Process.Pid {
								return checkpointUnitObservation{}, errors.New("synthetic unit collector saw a changed MainPID")
							}
							observedInvocation := invocation
							if changeSecond && expectedPID == launch.cmd.Process.Pid {
								observedInvocation = "1123456789abcdef0123456789abcdef"
							}
							return checkpointUnitObservation{MainPID: launch.cmd.Process.Pid, InvocationID: observedInvocation, ControlGroup: "/system.slice/llama-server.service", ActiveState: "active", SubState: "running", CgroupMembers: "/system.slice/llama-server.service"}, nil
						},
					}
				}
				unitRequest := CheckpointUnitIdentityRequest{Custody: store, Identity: identityReq, ExpectedAlias: launch.alias}
				t.Run("authenticated-unit-join", func(t *testing.T) {
					association, unitErr := observeCheckpointManagedUnitLinux(context.Background(), unitRequest, makeUnitSource(false))
					if unitErr != nil || association.Custody.EvidenceKind != binding.EvidenceKind || association.Identity.EvidenceKind != binding.EvidenceKind || association.Identity.ObservedMappedBytes != 0 {
						t.Fatalf("live authenticated controlled receipt failed to select and join the controlled local identity route: association=%+v err=%v", association, unitErr)
					}
				})
				t.Run("changed-second-unit-sample", func(t *testing.T) {
					if _, unitErr := observeCheckpointManagedUnitLinux(context.Background(), unitRequest, makeUnitSource(true)); unitErr == nil {
						t.Fatal("authenticated controlled unit join accepted a changed second synthetic unit sample")
					}
				})
			}
			if scenario.terminal {
				if err = launch.cmd.Process.Signal(syscall.SIGTERM); err != nil {
					t.Fatalf("stop committed controlled fixture child: %v", err)
				}
				waitCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_ = launch.WaitContext(waitCtx)
				cancel()
				if !launch.reaped || launch.executableFD != nil {
					t.Fatal("controlled terminal fixture did not reap the child and settle the executable pin")
				}
				if scenario.tamperedTerminal {
					originalIdentity := launch.controlledExecutableIdentity
					launch.controlledExecutableIdentity.Inode++
					if releaseErr := launch.ReleaseTerminal(context.Background()); releaseErr == nil {
						t.Fatal("terminal release accepted a mutated retained executable identity")
					}
					launch.controlledExecutableIdentity = originalIdentity
				}
				if err = launch.ReleaseTerminal(context.Background()); err != nil {
					t.Fatalf("controlled v2 terminal release rejected the retained executable identity after reap: %v", err)
				}
				started = false
			}
		})
	}
}

func TestCheckpointControlledSourceMappedFootprintUnionAndBounds(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "mapped-footprint-source-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	device := uint64(stat.Dev)
	inode := uint64(stat.Ino)
	deviceText := fmt.Sprintf("%x:%x", unix.Major(device), unix.Minor(device))
	mapsPath := filepath.Join(t.TempDir(), "maps")
	maps := fmt.Sprintf("1000-101e r--p 0 %s %d\n2000-201e r--p 14 %s %d\n3000-303c r--p 3c %s %d\n", deviceText, inode, deviceText, inode, deviceText, inode)
	if err = os.WriteFile(mapsPath, []byte(maps), 0600); err != nil {
		t.Fatal(err)
	}
	measured, err := checkpointMeasureModelMapped(context.Background(), mapsPath, device, inode, 100)
	if err != nil || measured != 90 {
		t.Fatalf("measured mapping union must combine overlap, retain gaps, and clamp EOF: bytes=%d err=%v", measured, err)
	}
	overflow := fmt.Sprintf("1000-ffffffffffffffff r--p 7fffffffffffffff %s %d\n", deviceText, inode)
	if err = os.WriteFile(mapsPath, []byte(overflow), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = checkpointMeasureModelMapped(context.Background(), mapsPath, device, inode, int64(1<<63-1)); err == nil {
		t.Fatal("mapping source offset plus virtual range length overflow was accepted")
	}
}

func TestCheckpointControlledSourceReceiptJSONIsStrict(t *testing.T) {
	valid := `{"receipt":{"version":2,"key_id":"k","nonce":"n","boot_id":"b","prelaunch_boot_ns":1,"start_boot_ns":1,"started_boot_ns":1,"pid":2,"start_ticks":3,"service_unit":"llama-server.service","unit_association":"label-only-unverified","endpoint":"http://127.0.0.1:8080","socket_inode":4,"executable_path":"/x","executable_sha256":"h","actual_alias":"a","source":{"canonical_path":"/m","device":1,"inode":2,"size":3,"sha256":"s","verity_digest":"v"},"evidence_kind":"controlled-source-fs-verity-v2","model_argument":"/proc/self/fd/4","argv_sha256":"a","executable":{"canonical_path":"/x","device":1,"inode":2,"size":3,"sha256":"h","verity_digest":"v"}},"signature":"sig"}`
	if err := strictControlledReceiptJSON([]byte(valid)); err != nil {
		t.Fatalf("valid controlled receipt rejected: %v", err)
	}
	mutations := map[string]string{
		"unknown":            strings.Replace(valid, `"signature":"sig"`, `"extra":true,"signature":"sig"`, 1),
		"duplicate":          strings.Replace(valid, `"version":2`, `"version":2,"version":2`, 1),
		"case-variant":       strings.Replace(valid, `"version":2`, `"Version":2`, 1),
		"null":               strings.Replace(valid, `"model_argument":"/proc/self/fd/4"`, `"model_argument":null`, 1),
		"missing-executable": strings.Replace(valid, `,"executable":{"canonical_path":"/x","device":1,"inode":2,"size":3,"sha256":"h","verity_digest":"v"}`, "", 1),
		"null-executable":    strings.Replace(valid, `"executable":{"canonical_path":"/x","device":1,"inode":2,"size":3,"sha256":"h","verity_digest":"v"}`, `"executable":null`, 1),
		"trailing":           valid + `{}`,
		"downgraded":         strings.Replace(valid, `"version":2`, `"version":1`, 1),
	}
	for name, raw := range mutations {
		t.Run(name, func(t *testing.T) {
			if err := strictControlledReceiptJSON([]byte(raw)); err == nil {
				t.Fatalf("accepted malformed controlled receipt: %s", name)
			}
		})
	}
}

func TestCheckpointControlledSourceLegacyReceiptKeepsPreLeafSignedShape(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	receipt := custodyReceipt{
		Version: 1, KeyID: custodyKeyID(public), Nonce: strings.Repeat("a", 64), BootID: "00000000-0000-0000-0000-000000000001",
		PrelaunchBootNS: 1, StartBootNS: 2, StartedBootNS: 3, PID: 42, StartTicks: 55, ServiceUnit: checkpointIdentityServiceUnit,
		UnitAssociation: "label-only-unverified", Endpoint: "http://127.0.0.1:8080", SocketInode: 66,
		ExecutablePath: "/private/launchers/server", ExecutableSHA256: strings.Repeat("b", 64), ActualAlias: "legacy-fixture",
		Source: custodySourceIdentity{CanonicalPath: "/private/models/model.gguf", Device: 7, Inode: 8, Size: 9, SHA256: strings.Repeat("c", 64), VerityDigest: strings.Repeat("d", 64)},
	}
	expected := fmt.Sprintf(`{"version":1,"key_id":%q,"nonce":%q,"boot_id":%q,"prelaunch_boot_ns":1,"start_boot_ns":2,"started_boot_ns":3,"pid":42,"start_ticks":55,"service_unit":%q,"unit_association":%q,"endpoint":%q,"socket_inode":66,"executable_path":%q,"executable_sha256":%q,"actual_alias":%q,"source":{"canonical_path":%q,"device":7,"inode":8,"size":9,"sha256":%q,"verity_digest":%q}}`,
		receipt.KeyID, receipt.Nonce, receipt.BootID, receipt.ServiceUnit, receipt.UnitAssociation, receipt.Endpoint, receipt.ExecutablePath, receipt.ExecutableSHA256, receipt.ActualAlias,
		receipt.Source.CanonicalPath, receipt.Source.SHA256, receipt.Source.VerityDigest)
	canonical, err := custodyReceiptBytes(receipt)
	if err != nil || string(canonical) != expected || bytes.Contains(canonical, []byte(`"executable"`)) {
		t.Fatalf("v1 receipt bytes differ from the pre-leaf signed shape: %s err=%v", canonical, err)
	}
	signature := ed25519.Sign(private, []byte(expected))
	if !ed25519.Verify(public, canonical, signature) {
		t.Fatal("pre-leaf-shaped v1 receipt signature positive control failed")
	}
	encoded, err := json.Marshal(custodySignedReceipt{Receipt: receipt, Signature: hex.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	var decoded custodySignedReceipt
	if err = json.Unmarshal(encoded, &decoded); err != nil || decoded.Receipt.Executable != nil || !ed25519.Verify(public, mustCustodyReceiptBytes(t, decoded.Receipt), signature) {
		t.Fatalf("old-shape signed receipt did not round-trip as legacy v1: err=%v", err)
	}
}

func mustCustodyReceiptBytes(t *testing.T, receipt custodyReceipt) []byte {
	t.Helper()
	encoded, err := custodyReceiptBytes(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

var custodyChildMapping []byte

func TestCustodyChildProcess(t *testing.T) {
	if os.Getenv("CHECKPOINT_CUSTODY_CHILD") != "1" {
		return
	}
	args := os.Args
	model := ""
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-m" || args[i] == "--model" {
			model = args[i+1]
		}
	}
	if model == "" || !filepath.IsAbs(model) {
		t.Fatal("controlled child did not receive prepared path as its model argument")
	}
	if os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_CHILD") == "1" {
		if model != "/proc/self/fd/4" {
			t.Fatal("controlled-source child did not receive the exact descriptor-four model argument")
		}
		fd := os.NewFile(4, "controlled-source-model")
		if fd == nil {
			t.Fatal("controlled-source child did not inherit descriptor four")
		}
		if os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_SWAP_PATH") != "" || os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_FIFO") != "" {
			if err := fd.Close(); err != nil {
				t.Fatal(err)
			}
			fd = nil
		}
		if swapPath := os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_SWAP_PATH"); swapPath != "" {
			replacement, err := os.Open(swapPath)
			if err != nil {
				t.Fatal(err)
			}
			if replacement.Fd() == 4 {
				fd = replacement
			} else {
				if err = unix.Dup2(int(replacement.Fd()), 4); err != nil {
					replacement.Close()
					t.Fatal(err)
				}
				_ = replacement.Close()
				fd = os.NewFile(4, "controlled-source-replacement")
			}
		}
		if fifoPath := os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_FIFO"); fifoPath != "" {
			fifoFD, err := unix.Open(fifoPath, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if fifoFD != 4 {
				if err = unix.Dup2(fifoFD, 4); err != nil {
					unix.Close(fifoFD)
					t.Fatal(err)
				}
				unix.Close(fifoFD)
			}
			fd = os.NewFile(4, "controlled-source-fifo")
		}
		if fd != nil {
			if _, err := fd.Stat(); err != nil {
				t.Fatalf("controlled-source child descriptor four is not live: %v", err)
			}
		}
		if os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_PARTIAL_MAP") == "1" {
			st, err := fd.Stat()
			if err != nil {
				t.Fatal(err)
			}
			mapping, err := syscall.Mmap(4, 0, int(st.Size()/2), syscall.PROT_READ, syscall.MAP_PRIVATE)
			if err != nil {
				t.Fatal(err)
			}
			custodyChildMapping = mapping
		}
		if os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_WRONG_ARGV") == "1" {
			for _, arg := range os.Args {
				if arg == "/proc/self/fd/4" {
					bytes := unsafe.Slice(unsafe.StringData(arg), len(arg))
					bytes[len(bytes)-1] = '5'
				}
			}
		}
		ln, err := net.Listen("tcp", os.Getenv("CHECKPOINT_CUSTODY_ENDPOINT"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		if marker := os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_CLOSE_LISTENER"); marker != "" {
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(marker); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err := os.Stat(marker); err != nil {
				t.Fatal("controlled-source parent did not request listener drift")
			}
			if err := ln.Close(); err != nil {
				t.Fatal(err)
			}
		}
		if os.Getenv("CHECKPOINT_CONTROLLED_SOURCE_CLOSE_FD") == "1" {
			if err := fd.Close(); err != nil {
				t.Fatal(err)
			}
			fd = nil
		}
		for {
			time.Sleep(time.Second)
		}
	}
	var ln net.Listener
	var err error
	if os.Getenv("CHECKPOINT_CUSTODY_DELAY_MODEL") == "1" {
		ln, err = net.Listen("tcp", os.Getenv("CHECKPOINT_CUSTODY_ENDPOINT"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err = os.Stat(os.Getenv("CHECKPOINT_CUSTODY_RELEASE_MODEL")); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if _, err = os.Stat(os.Getenv("CHECKPOINT_CUSTODY_RELEASE_MODEL")); err != nil {
			t.Fatal("parent did not release delayed model open")
		}
	}
	f, err := os.OpenFile(model, os.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	mapSize := int(info.Size())
	if os.Getenv("CHECKPOINT_CUSTODY_PARTIAL_MAPPING") == "1" {
		mapSize /= 2
	}
	custodyChildMapping, err = syscall.Mmap(int(f.Fd()), 0, mapSize, syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		t.Fatal(err)
	}
	if opened := os.Getenv("CHECKPOINT_CUSTODY_MODEL_OPENED"); opened != "" {
		if err = os.WriteFile(opened, []byte("opened"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if ln == nil {
		ln, err = net.Listen("tcp", os.Getenv("CHECKPOINT_CUSTODY_ENDPOINT"))
		if err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("CHECKPOINT_CUSTODY_DELAY_MODEL") != "1" {
		defer ln.Close()
	}
	for {
		time.Sleep(time.Second)
	}
}

func testModelDescriptorSurvivesPathReplacement(t *testing.T, store *CheckpointCustodyStore, base, modelPath, sourceSHA string, sourceSize int64, executable string, executableSum [32]byte) {
	t.Helper()
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: sourceSize})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	release := filepath.Join(base, "release-model-open")
	opened := filepath.Join(base, "model-opened")
	cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr, "CHECKPOINT_CUSTODY_DELAY_MODEL=1", "CHECKPOINT_CUSTODY_RELEASE_MODEL="+release, "CHECKPOINT_CUSTODY_MODEL_OPENED="+opened)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "descriptor-race-fixture", ExpectedExecutableSHA256: hex.EncodeToString(executableSum[:])})
	if err != nil {
		t.Fatal(err)
	}
	started := false
	waited := false
	defer func() {
		if !started {
			_ = launch.Abort()
		} else if !waited {
			_ = stopCustodyTestChild(launch)
		}
	}()
	if err = launch.Start(); err != nil {
		t.Fatalf("start descriptor-race child: %v", err)
	}
	started = true
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		t.Fatal("descriptor-race child did not bind before opening model")
	}
	moved := model.path + ".racing"
	if err = os.Rename(model.path, moved); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(model.path, []byte("replaced model path"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(release, []byte("open now"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err = os.Stat(opened); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = os.Stat(opened); err != nil {
		t.Fatal("child did not open the inherited immutable model descriptor")
	}
	if err = os.Remove(model.path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(moved, model.path); err != nil {
		t.Fatal(err)
	}
	if err = launch.Commit(context.Background()); err != nil {
		t.Fatalf("custody rejection assertion: model pathname replacement redirected the controlled child: %v", err)
	}
	_, valid, err := store.VerifyBinding(context.Background(), "http://"+addr, checkpointIdentityServiceUnit)
	if err != nil || !valid {
		t.Fatalf("descriptor-backed model launch did not produce verifiable local receipt: valid=%v err=%v", valid, err)
	}
	if err = stopCustodyTestChild(launch); err == nil {
		t.Fatal("descriptor-race child unexpectedly exited successfully")
	}
	waited = true
	if err = os.Remove(custodyReceiptPath(store.root, launch.nonce)); err != nil {
		t.Fatal(err)
	}
}

func testCommitCancellationDuringObservation(t *testing.T, store *CheckpointCustodyStore, base, modelPath, sourceSHA string, sourceSize int64, executable string, executableSum [32]byte) {
	t.Helper()
	model, err := store.Prepare(context.Background(), CheckpointCustodySource{Path: modelPath, ApprovedSHA256: sourceSHA, ExpectedBytes: sourceSize})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	probe.Close()
	cmd := exec.Command(executable, "-test.run=^TestCustodyChildProcess$", "--", "-m", "{CHECKPOINT_MODEL}")
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	cmd.Env = append(os.Environ(), "CHECKPOINT_CUSTODY_CHILD=1", "CHECKPOINT_CUSTODY_ENDPOINT="+addr)
	launch, err := store.Begin(model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + addr, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: "commit-cancel-fixture", ExpectedExecutableSHA256: hex.EncodeToString(executableSum[:])})
	if err != nil {
		t.Fatal(err)
	}
	started := false
	waited := false
	defer func() {
		if !started {
			_ = launch.Abort()
		} else if !waited {
			_ = stopCustodyTestChild(launch)
		}
	}()
	if err = launch.Start(); err != nil {
		t.Fatal(err)
	}
	started = true
	if !waitForCustodyEndpoint(addr, 5*time.Second) {
		t.Fatal("commit-cancel child did not bind")
	}
	entered := make(chan struct{})
	launch.commitTestEntered = entered
	launch.commitTestBarrier = make(chan struct{})
	commitResult := make(chan error, 1)
	go func() { commitResult <- launch.Commit(context.Background()) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("commit did not enter its cancellable process-observation path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	waitErr := launch.WaitContext(ctx)
	cancel()
	waited = true
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("WaitContext did not report bounded cancellation while Commit was observing: %v", waitErr)
	}
	select {
	case commitErr := <-commitResult:
		if commitErr == nil {
			t.Fatal("canceled late Commit reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled Commit did not leave its observation path")
	}
	if _, err = os.Lstat(custodyReceiptPath(store.root, launch.nonce)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled/reaped child left a custody receipt: %v", err)
	}
}

func waitForCustodyEndpoint(addr string, timeout time.Duration) bool {
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			c.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
func mustReceiptBytesForTest(t *testing.T, r custodyReceipt) []byte {
	t.Helper()
	b, e := custodyReceiptBytes(r)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func writeCustodyReceiptForTest(t *testing.T, path string, r custodySignedReceipt) {
	t.Helper()
	b, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func stopCustodyTestChild(l *CheckpointControlledLaunch) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	return l.WaitContext(ctx)
}
