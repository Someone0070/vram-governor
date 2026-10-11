//go:build linux

package nodeagent

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
	"vram-governor/internal/safefile"
)

const (
	checkpointProcMaxRead = 64 << 20
	checkpointFDLimit     = 65536
)

type checkpointLinuxSource struct {
	procRoot          string
	mainPID           func(context.Context, string) (int, error)
	beforeFinalSample func()
}

var checkpointModelHashCache = struct {
	sync.Mutex
	byIdentity map[string]string
}{byIdentity: make(map[string]string)}

var checkpointExecutableHashCache = struct {
	sync.Mutex
	byIdentity map[string]string
}{byIdentity: make(map[string]string)}

func observeCheckpointIdentityPlatform(ctx context.Context, req CheckpointIdentityRequest, endpoint string, host net.IP, port uint16) (CheckpointLocalIdentity, error) {
	source := checkpointLinuxSource{
		procRoot: "/proc",
		mainPID:  checkpointSystemdMainPID,
	}
	return observeCheckpointIdentityLinux(ctx, req, endpoint, host, port, source)
}

func checkpointSystemdMainPID(ctx context.Context, unit string) (int, error) {
	// The unit is already compared against a fixed compile-time allowlist.
	cmd := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=MainPID", "--value")
	buf := &checkpointBoundedBuffer{limit: 128}
	cmd.Stdout, cmd.Stderr = buf, buf
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("read managed service MainPID: %w", err)
	}
	text := strings.TrimSpace(buf.String())
	if text == "" || len(text) > 10 {
		return 0, errors.New("managed service MainPID is empty or malformed")
	}
	for _, c := range text {
		if c < '0' || c > '9' {
			return 0, errors.New("managed service MainPID is malformed")
		}
	}
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 1 {
		return 0, errors.New("managed service is not running with a valid MainPID")
	}
	return pid, nil
}

type checkpointBoundedBuffer struct {
	mu    sync.Mutex
	bytes []byte
	limit int
}

func (b *checkpointBoundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.bytes)+len(p) > b.limit {
		return 0, errors.New("bounded command output exceeded")
	}
	b.bytes = append(b.bytes, p...)
	return len(p), nil
}

func (b *checkpointBoundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.bytes)
}

func observeCheckpointIdentityLinux(ctx context.Context, req CheckpointIdentityRequest, endpoint string, host net.IP, port uint16, source checkpointLinuxSource) (CheckpointLocalIdentity, error) {
	return observeCheckpointIdentityLinuxWithBinding(ctx, req, endpoint, host, port, source, nil)
}

func observeCheckpointIdentityControlledLinux(ctx context.Context, req CheckpointIdentityRequest, endpoint string, host net.IP, port uint16, source checkpointLinuxSource, binding CheckpointCustodyVerification) (CheckpointLocalIdentity, error) {
	if binding.EvidenceKind != "controlled-source-fs-verity-v2" || binding.ModelArgument != "/proc/self/fd/4" || !custodyDigestRE.MatchString(binding.ArgvSHA256) {
		return CheckpointLocalIdentity{}, errors.New("controlled identity requires an authenticated v2 custody binding")
	}
	return observeCheckpointIdentityLinuxWithBinding(ctx, req, endpoint, host, port, source, &binding)
}

func observeCheckpointIdentityLinuxWithBinding(ctx context.Context, req CheckpointIdentityRequest, endpoint string, host net.IP, port uint16, source checkpointLinuxSource, controlled *CheckpointCustodyVerification) (CheckpointLocalIdentity, error) {
	if req.ServiceUnit != checkpointIdentityServiceUnit {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity service unit is not allowlisted")
	}
	if source.procRoot == "" || source.mainPID == nil {
		return CheckpointLocalIdentity{}, errors.New("checkpoint identity source is incomplete")
	}
	bootBefore, err := checkpointReadBounded(filepath.Join(source.procRoot, "sys/kernel/random/boot_id"), 128)
	if err != nil {
		return CheckpointLocalIdentity{}, fmt.Errorf("read kernel boot identity: %w", err)
	}
	bootID := strings.TrimSpace(string(bootBefore))
	bootParts := strings.Split(bootID, "-")
	validBootID := len(bootParts) == 5 && len(bootParts[0]) == 8 && len(bootParts[1]) == 4 && len(bootParts[2]) == 4 && len(bootParts[3]) == 4 && len(bootParts[4]) == 12
	if validBootID {
		_, decodeErr := hex.DecodeString(strings.Join(bootParts, ""))
		validBootID = decodeErr == nil
	}
	if !validBootID {
		return CheckpointLocalIdentity{}, errors.New("kernel boot identity is malformed")
	}
	pid, err := source.mainPID(ctx, req.ServiceUnit)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	procDir := filepath.Join(source.procRoot, strconv.Itoa(pid))
	startBefore, err := checkpointProcessStart(procDir, pid)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	listeners, err := checkpointMatchingListeners(ctx, source.procRoot, host, port)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	if len(listeners) != 1 {
		return CheckpointLocalIdentity{}, fmt.Errorf("checkpoint endpoint has %d matching listener sockets; expected exactly one", len(listeners))
	}
	listener := listeners[0]
	owned, err := checkpointProcessOwnsSocket(ctx, procDir, listener.inode)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	if !owned {
		return CheckpointLocalIdentity{}, errors.New("managed service MainPID does not own the configured listener socket")
	}
	exePath, err := os.Readlink(filepath.Join(procDir, "exe"))
	if err != nil || exePath == "" || strings.HasSuffix(exePath, " (deleted)") {
		return CheckpointLocalIdentity{}, errors.New("managed service executable identity is unavailable or deleted")
	}
	exePath = filepath.Clean(exePath)
	exe, err := os.Open(filepath.Join(procDir, "exe"))
	if err != nil {
		return CheckpointLocalIdentity{}, fmt.Errorf("open running executable identity: %w", err)
	}
	exeBefore, err := checkpointExecutableFileStat(exe)
	if err != nil || exeBefore.size <= 0 || exeBefore.size > checkpointIdentityMaxExe {
		_ = exe.Close()
		return CheckpointLocalIdentity{}, errors.New("running executable file identity is outside safe bounds")
	}
	exeKey := fmt.Sprintf("%s\x00%d:%d:%d:%d:%d:%d:%d", exePath, pid, startBefore, exeBefore.device, exeBefore.inode, exeBefore.size, exeBefore.mtime, exeBefore.ctime)
	checkpointExecutableHashCache.Lock()
	exeDigest, exeCached := checkpointExecutableHashCache.byIdentity[exeKey]
	checkpointExecutableHashCache.Unlock()
	if !exeCached {
		exeDigest, err = checkpointHashOpened(ctx, exe, checkpointIdentityMaxExe)
	}
	exeAfter, statErr := checkpointExecutableFileStat(exe)
	closeErr := exe.Close()
	if err != nil || statErr != nil || closeErr != nil {
		return CheckpointLocalIdentity{}, errors.Join(err, statErr, closeErr)
	}
	if exeBefore != exeAfter {
		return CheckpointLocalIdentity{}, errors.New("running executable changed while being hashed")
	}
	if !strings.EqualFold(exeDigest, req.ExpectedExecutableSHA256) {
		return CheckpointLocalIdentity{}, errors.New("running executable does not match the configured allowlist")
	}
	model, err := checkpointObserveModel(ctx, req)
	if err != nil {
		return CheckpointLocalIdentity{}, err
	}
	defer model.file.Close()
	mappedBytes := int64(0)
	if controlled == nil {
		mappedBytes, err = checkpointVerifyModelMapped(ctx, filepath.Join(procDir, "maps"), model.device, model.inode, model.size)
		if err != nil {
			return CheckpointLocalIdentity{}, err
		}
	} else {
		if controlled.PID != pid || controlled.BootID != bootID || controlled.ProcessStartTicks != startBefore || controlled.ListenerSocketInode != listener.inode || controlled.ArtifactPath != model.path || controlled.ArtifactDevice != model.device || controlled.ArtifactInode != model.inode || controlled.ArtifactSize != model.size || !strings.EqualFold(controlled.ArtifactSHA256, model.sha256) {
			return CheckpointLocalIdentity{}, errors.New("controlled receipt differs from the observed model source or process")
		}
		pin, pinErr := openCustodyReceiptSource(custodySourceIdentity{CanonicalPath: controlled.ArtifactPath, Device: controlled.ArtifactDevice, Inode: controlled.ArtifactInode, Size: controlled.ArtifactSize, SHA256: controlled.ArtifactSHA256, VerityDigest: controlled.VerityDigest})
		if pinErr != nil {
			return CheckpointLocalIdentity{}, pinErr
		}
		executable := custodySourceIdentity{CanonicalPath: controlled.ExecutablePath, Device: controlled.ExecutableDevice, Inode: controlled.ExecutableInode, Size: controlled.ExecutableSize, SHA256: controlled.ExecutableSHA256, VerityDigest: controlled.ExecutableVerityDigest}
		executablePin, executableErr := openCustodyReceiptExecutable(executable)
		if executableErr != nil {
			pin.Close()
			return CheckpointLocalIdentity{}, executableErr
		}
		_, verifyErr := custodyLiveControlledProcess(ctx, pid, custodySourceIdentity{CanonicalPath: controlled.ArtifactPath, Device: controlled.ArtifactDevice, Inode: controlled.ArtifactInode, Size: controlled.ArtifactSize, SHA256: controlled.ArtifactSHA256, VerityDigest: controlled.VerityDigest}, pin, executable, executablePin, endpoint, req.ExpectedExecutableSHA256, controlled.ArgvSHA256, controlled.ModelArgument)
		executablePin.Close()
		pin.Close()
		if verifyErr != nil {
			return CheckpointLocalIdentity{}, verifyErr
		}
		mappedBytes, err = checkpointMeasureModelMapped(ctx, filepath.Join(procDir, "maps"), model.device, model.inode, model.size)
		if err != nil {
			return CheckpointLocalIdentity{}, err
		}
	}
	if source.beforeFinalSample != nil {
		source.beforeFinalSample()
	}
	startAfter, err := checkpointProcessStart(procDir, pid)
	if err != nil || startAfter != startBefore {
		return CheckpointLocalIdentity{}, errors.New("managed service process incarnation changed during observation")
	}
	mainPIDAfter, err := source.mainPID(ctx, req.ServiceUnit)
	if err != nil || mainPIDAfter != pid {
		return CheckpointLocalIdentity{}, errors.New("managed service MainPID changed during observation")
	}
	bootAfter, err := checkpointReadBounded(filepath.Join(source.procRoot, "sys/kernel/random/boot_id"), 128)
	if err != nil || strings.TrimSpace(string(bootAfter)) != bootID {
		return CheckpointLocalIdentity{}, errors.New("kernel boot identity changed during observation")
	}
	listenersAfter, err := checkpointMatchingListeners(ctx, source.procRoot, host, port)
	if err != nil || len(listenersAfter) != 1 || listenersAfter[0].inode != listener.inode {
		return CheckpointLocalIdentity{}, errors.New("configured listener identity changed during observation")
	}
	ownedAfter, err := checkpointProcessOwnsSocket(ctx, procDir, listener.inode)
	if err != nil || !ownedAfter {
		return CheckpointLocalIdentity{}, errors.New("managed service no longer owns the configured listener")
	}
	exePathAfter, linkErr := os.Readlink(filepath.Join(procDir, "exe"))
	exeInfoAfter, exeStatErr := os.Stat(filepath.Join(procDir, "exe"))
	if linkErr != nil || exeStatErr != nil || filepath.Clean(exePathAfter) != exePath {
		return CheckpointLocalIdentity{}, errors.New("managed service executable changed during observation")
	}
	exeAfterStat, ok := exeInfoAfter.Sys().(*syscall.Stat_t)
	if !ok {
		return CheckpointLocalIdentity{}, errors.New("managed service executable file identity is unavailable")
	}
	exeAfterIdentity := checkpointExecutableStat{device: uint64(exeAfterStat.Dev), inode: exeAfterStat.Ino, size: exeInfoAfter.Size(), mtime: exeAfterStat.Mtim.Sec*1e9 + exeAfterStat.Mtim.Nsec, ctime: exeAfterStat.Ctim.Sec*1e9 + exeAfterStat.Ctim.Nsec}
	if exeAfterIdentity != exeBefore {
		return CheckpointLocalIdentity{}, errors.New("managed service executable file changed during observation")
	}
	if !exeCached {
		checkpointExecutableHashCache.Lock()
		if len(checkpointExecutableHashCache.byIdentity) >= 64 {
			checkpointExecutableHashCache.byIdentity = make(map[string]string)
		}
		checkpointExecutableHashCache.byIdentity[exeKey] = exeDigest
		checkpointExecutableHashCache.Unlock()
	}
	if err := checkpointValidateOpenedModel(model, req); err != nil {
		return CheckpointLocalIdentity{}, err
	}
	if controlled == nil {
		mappedBytesAfter, mapErr := checkpointVerifyModelMapped(ctx, filepath.Join(procDir, "maps"), model.device, model.inode, model.size)
		if mapErr != nil || mappedBytesAfter != mappedBytes {
			return CheckpointLocalIdentity{}, errors.New("observed GGUF mapping changed during observation")
		}
	} else {
		pin, pinErr := openCustodyReceiptSource(custodySourceIdentity{CanonicalPath: controlled.ArtifactPath, Device: controlled.ArtifactDevice, Inode: controlled.ArtifactInode, Size: controlled.ArtifactSize, SHA256: controlled.ArtifactSHA256, VerityDigest: controlled.VerityDigest})
		if pinErr != nil {
			return CheckpointLocalIdentity{}, pinErr
		}
		executable := custodySourceIdentity{CanonicalPath: controlled.ExecutablePath, Device: controlled.ExecutableDevice, Inode: controlled.ExecutableInode, Size: controlled.ExecutableSize, SHA256: controlled.ExecutableSHA256, VerityDigest: controlled.ExecutableVerityDigest}
		executablePin, executableErr := openCustodyReceiptExecutable(executable)
		if executableErr != nil {
			pin.Close()
			return CheckpointLocalIdentity{}, executableErr
		}
		_, verifyErr := custodyLiveControlledProcess(ctx, pid, custodySourceIdentity{CanonicalPath: controlled.ArtifactPath, Device: controlled.ArtifactDevice, Inode: controlled.ArtifactInode, Size: controlled.ArtifactSize, SHA256: controlled.ArtifactSHA256, VerityDigest: controlled.VerityDigest}, pin, executable, executablePin, endpoint, req.ExpectedExecutableSHA256, controlled.ArgvSHA256, controlled.ModelArgument)
		executablePin.Close()
		pin.Close()
		mappedBytesAfter, mapErr := checkpointMeasureModelMapped(ctx, filepath.Join(procDir, "maps"), model.device, model.inode, model.size)
		if verifyErr != nil || mapErr != nil || mappedBytesAfter != mappedBytes {
			return CheckpointLocalIdentity{}, errors.New("controlled source or observed mapping changed during identity observation")
		}
	}
	finalStart, err := checkpointProcessStart(procDir, pid)
	if err != nil || finalStart != startBefore {
		return CheckpointLocalIdentity{}, errors.New("managed service process incarnation changed before identity return")
	}
	id := CheckpointLocalIdentity{
		EvidenceKind: "mapped-file-v1",
		Endpoint:     endpoint, ServiceUnit: req.ServiceUnit, BootID: bootID,
		PID: pid, ProcessStartTicks: startBefore,
		ListenerIP: listener.ip.String(), ListenerPort: port, ListenerSocketInode: listener.inode,
		ExecutablePath: exePath, ExecutableSHA256: exeDigest,
		ExecutableDevice: exeBefore.device, ExecutableInode: exeBefore.inode, ExecutableSize: exeBefore.size,
		ModelPath: model.path, ModelSHA256: model.sha256,
		ModelDevice: model.device, ModelInode: model.inode, ModelSize: model.size,
		ObservedMappedBytes: mappedBytes,
	}
	if controlled != nil {
		id.EvidenceKind = "controlled-source-fs-verity-v2"
	}
	id.Fingerprint = checkpointIdentityFingerprint(id)
	return id, nil
}

func checkpointReadBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("kernel observation exceeded its byte bound")
	}
	return b, nil
}

func checkpointProcessStart(procDir string, pid int) (uint64, error) {
	b, err := checkpointReadBounded(filepath.Join(procDir, "stat"), 64<<10)
	if err != nil {
		return 0, fmt.Errorf("read managed process incarnation: %w", err)
	}
	text := strings.TrimSpace(string(b))
	open, close := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if open < 1 || close <= open || close+2 >= len(text) {
		return 0, errors.New("managed process stat record is malformed")
	}
	observedPID, err := strconv.Atoi(strings.TrimSpace(text[:open]))
	if err != nil || observedPID != pid {
		return 0, errors.New("managed process PID was reused during observation")
	}
	fields := strings.Fields(text[close+1:]) // begins at field 3 (state)
	if len(fields) <= 19 {
		return 0, errors.New("managed process stat record is incomplete")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64) // field 22: starttime
	if err != nil || start == 0 {
		return 0, errors.New("managed process starttime is invalid")
	}
	return start, nil
}

type checkpointListener struct {
	inode uint64
	ip    net.IP
}

func checkpointMatchingListeners(ctx context.Context, procRoot string, target net.IP, targetPort uint16) ([]checkpointListener, error) {
	type source struct {
		name string
		ipv6 bool
	}
	sources := []source{{"net/tcp", false}, {"net/tcp6", true}}
	var matches []checkpointListener
	for _, item := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		b, err := checkpointReadBounded(filepath.Join(procRoot, item.name), checkpointProcMaxRead)
		if err != nil {
			return nil, fmt.Errorf("read local TCP listener table: %w", err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(b)))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			if lineNo%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
			}
			if lineNo == 1 {
				continue
			}
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				return nil, errors.New("kernel TCP listener table has a partial row")
			}
			if fields[3] != "0A" {
				continue
			}
			ip, port, err := checkpointDecodeProcAddress(fields[1], item.ipv6)
			if err != nil {
				return nil, fmt.Errorf("kernel TCP listener table has an invalid address: %w", err)
			}
			if port != targetPort || !ip.Equal(target) {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || inode == 0 {
				return nil, errors.New("kernel TCP listener has an invalid socket inode")
			}
			matches = append(matches, checkpointListener{inode: inode, ip: ip})
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	return matches, nil
}

func checkpointDecodeProcAddress(raw string, ipv6 bool) (net.IP, uint16, error) {
	parts := strings.Split(raw, ":")
	wantParts := 2
	if len(parts) != wantParts {
		return nil, 0, errors.New("address has invalid field count")
	}
	portN, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return nil, 0, err
	}
	encoded, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, 0, err
	}
	if ipv6 {
		if len(encoded) != 16 {
			return nil, 0, errors.New("IPv6 address has invalid length")
		}
		decoded := make([]byte, 16)
		for word := 0; word < 4; word++ {
			decoded[word*4], decoded[word*4+1], decoded[word*4+2], decoded[word*4+3] = encoded[word*4+3], encoded[word*4+2], encoded[word*4+1], encoded[word*4]
		}
		return net.IP(decoded), uint16(portN), nil
	}
	if len(encoded) != 4 {
		return nil, 0, errors.New("IPv4 address has invalid length")
	}
	return net.IPv4(encoded[3], encoded[2], encoded[1], encoded[0]), uint16(portN), nil
}

func checkpointProcessOwnsSocket(ctx context.Context, procDir string, inode uint64) (bool, error) {
	fds, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return false, fmt.Errorf("inspect managed process socket descriptors: %w", err)
	}
	if len(fds) > checkpointFDLimit {
		return false, errors.New("managed process has too many descriptors to inspect safely")
	}
	count := 0
	for _, fd := range fds {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if _, err := strconv.ParseUint(fd.Name(), 10, 32); err != nil {
			return false, errors.New("managed process descriptor directory is malformed")
		}
		target, err := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // transient descriptor closure; a missing listener still fails below
			}
			return false, fmt.Errorf("read managed process descriptor identity: %w", err)
		}
		if target == fmt.Sprintf("socket:[%d]", inode) {
			count++
		}
	}
	if count > 1 {
		return false, errors.New("managed process owns the listener through ambiguous descriptors")
	}
	return count == 1, nil
}

type checkpointOpenedModel struct {
	file     *os.File
	path     string
	cacheKey string
	sha256   string
	device   uint64
	inode    uint64
	size     int64
	stat     checkpointFileStat
}

func checkpointObserveModel(ctx context.Context, req CheckpointIdentityRequest) (checkpointOpenedModel, error) {
	for _, component := range strings.Split(req.ModelPath, string(filepath.Separator)) {
		if component == ".." {
			return checkpointOpenedModel{}, errors.New("checkpoint model path contains traversal")
		}
	}
	modelPath, err := filepath.Abs(req.ModelPath)
	if err != nil {
		return checkpointOpenedModel{}, err
	}
	modelPath = filepath.Clean(modelPath)
	if err := checkpointModelPathAllowed(req, modelPath); err != nil {
		return checkpointOpenedModel{}, err
	}
	f, err := safefile.OpenReadOnlyNoFollow(modelPath)
	if err != nil {
		return checkpointOpenedModel{}, fmt.Errorf("open allowlisted checkpoint model: %w", err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = f.Close()
		}
	}()
	before, err := checkpointModelStat(f)
	if err != nil {
		return checkpointOpenedModel{}, err
	}
	if before.size <= 0 || before.size > checkpointIdentityMaxModel {
		return checkpointOpenedModel{}, errors.New("checkpoint model size is outside safe bounds")
	}
	if before.links != 1 {
		return checkpointOpenedModel{}, errors.New("checkpoint model has ambiguous hard links")
	}
	fdPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	if err != nil || filepath.Clean(fdPath) != modelPath {
		return checkpointOpenedModel{}, errors.New("opened checkpoint model path does not match its canonical path")
	}
	key := fmt.Sprintf("%s\x00%d:%d:%d:%d:%d:%d", modelPath, before.device, before.inode, before.size, before.mtime, before.ctime, before.links)
	checkpointModelHashCache.Lock()
	digest, cached := checkpointModelHashCache.byIdentity[key]
	checkpointModelHashCache.Unlock()
	if !cached {
		digest, err = checkpointHashOpened(ctx, f, checkpointIdentityMaxModel)
		if err != nil {
			return checkpointOpenedModel{}, fmt.Errorf("hash opened checkpoint model: %w", err)
		}
	}
	after, err := checkpointModelStat(f)
	if err != nil || before != after {
		return checkpointOpenedModel{}, errors.New("checkpoint model changed while its opened descriptor was being observed")
	}
	if !strings.EqualFold(digest, req.ExpectedModelSHA256) {
		return checkpointOpenedModel{}, errors.New("opened checkpoint model does not match the configured SHA-256 allowlist")
	}
	opened := checkpointOpenedModel{file: f, path: modelPath, cacheKey: key, sha256: digest, device: before.device, inode: before.inode, size: before.size, stat: before}
	if err := checkpointValidateOpenedModel(opened, req); err != nil {
		return checkpointOpenedModel{}, err
	}
	if !cached {
		checkpointModelHashCache.Lock()
		if len(checkpointModelHashCache.byIdentity) >= 64 {
			checkpointModelHashCache.byIdentity = make(map[string]string)
		}
		checkpointModelHashCache.byIdentity[key] = digest
		checkpointModelHashCache.Unlock()
	}
	keepOpen = true
	return opened, nil
}

func checkpointModelPathAllowed(req CheckpointIdentityRequest, modelPath string) error {
	for _, component := range strings.Split(modelPath, string(filepath.Separator)) {
		if component == ".." {
			return errors.New("checkpoint model path contains traversal")
		}
	}
	resolvedModel, err := filepath.EvalSymlinks(modelPath)
	if err != nil || filepath.Clean(resolvedModel) != modelPath {
		return errors.New("checkpoint model path contains a symlink or cannot be canonicalized")
	}
	for _, root := range req.ApprovedModelRoots {
		if root == "" || len(root) > 4096 || !filepath.IsAbs(root) {
			continue
		}
		for _, component := range strings.Split(root, string(filepath.Separator)) {
			if component == ".." {
				return errors.New("approved checkpoint model root contains traversal")
			}
		}
		cleanRoot := filepath.Clean(root)
		resolvedRoot, rootErr := filepath.EvalSymlinks(cleanRoot)
		if rootErr != nil || filepath.Clean(resolvedRoot) != cleanRoot {
			continue
		}
		rel, relErr := filepath.Rel(cleanRoot, modelPath)
		if relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil
		}
	}
	return errors.New("checkpoint model path is outside canonical approved roots")
}

func checkpointValidateOpenedModel(model checkpointOpenedModel, req CheckpointIdentityRequest) error {
	if model.file == nil {
		return errors.New("checkpoint model descriptor was not retained through observation")
	}
	current, err := checkpointModelStat(model.file)
	if err != nil || current != model.stat {
		return errors.New("checkpoint model changed while its descriptor was being observed")
	}
	if err := checkpointModelPathAllowed(req, model.path); err != nil {
		return err
	}
	linkInfo, err := os.Lstat(model.path)
	if err != nil || linkInfo.Mode()&os.ModeSymlink != 0 || !linkInfo.Mode().IsRegular() {
		return errors.New("checkpoint model path changed to a symlink or non-regular file")
	}
	fdPath, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", model.file.Fd()))
	if err != nil || filepath.Clean(fdPath) != model.path {
		return errors.New("opened checkpoint model descriptor no longer resolves to its canonical path")
	}
	pathInfo, err := os.Stat(model.path)
	if err != nil {
		return errors.New("checkpoint model pathname changed during observation")
	}
	pathStat, ok := pathInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(pathStat.Dev) != current.device || pathStat.Ino != current.inode || pathInfo.Size() != current.size {
		return errors.New("checkpoint model pathname no longer names the stable opened file")
	}
	return nil
}

type checkpointFileStat struct {
	device uint64
	inode  uint64
	size   int64
	mtime  int64
	ctime  int64
	links  uint64
}

type checkpointExecutableStat struct {
	device uint64
	inode  uint64
	size   int64
	mtime  int64
	ctime  int64
}

func checkpointExecutableFileStat(f *os.File) (checkpointExecutableStat, error) {
	info, err := f.Stat()
	if err != nil {
		return checkpointExecutableStat{}, err
	}
	if !info.Mode().IsRegular() {
		return checkpointExecutableStat{}, errors.New("running executable is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return checkpointExecutableStat{}, errors.New("running executable file identity is unavailable")
	}
	return checkpointExecutableStat{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), mtime: stat.Mtim.Sec*1e9 + stat.Mtim.Nsec, ctime: stat.Ctim.Sec*1e9 + stat.Ctim.Nsec}, nil
}

func checkpointModelStat(f *os.File) (checkpointFileStat, error) {
	info, err := f.Stat()
	if err != nil {
		return checkpointFileStat{}, err
	}
	if !info.Mode().IsRegular() {
		return checkpointFileStat{}, errors.New("checkpoint model is not a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return checkpointFileStat{}, errors.New("checkpoint model identity is unavailable")
	}
	return checkpointFileStat{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), mtime: stat.Mtim.Sec*1e9 + stat.Mtim.Nsec, ctime: stat.Ctim.Sec*1e9 + stat.Ctim.Nsec, links: uint64(stat.Nlink)}, nil
}

func checkpointHashOpened(ctx context.Context, f *os.File, maxBytes int64) (string, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	buf := make([]byte, 1<<20)
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, readErr := f.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > maxBytes {
				return "", errors.New("opened file exceeds the hashing limit")
			}
			if _, err := h.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
		if n == 0 {
			return "", io.ErrNoProgress
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type checkpointMapSegment struct{ start, end uint64 }

// checkpointMeasureModelMapped reports the union of mapped source offsets.
// Unlike the legacy eligibility check, it accepts an unmapped or partially
// mapped file because controlled-source provenance is established separately.
func checkpointMeasureModelMapped(ctx context.Context, mapsPath string, device, inode uint64, fileSize int64) (int64, error) {
	if fileSize < 0 {
		return 0, errors.New("managed model file size is negative")
	}
	b, err := checkpointReadBounded(mapsPath, checkpointProcMaxRead)
	if err != nil {
		return 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	segments := make([]checkpointMapSegment, 0, 8)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return 0, errors.New("managed process mapping table has a partial row")
		}
		mappedInode, parseErr := strconv.ParseUint(fields[4], 10, 64)
		if parseErr != nil {
			return 0, errors.New("managed process mapping inode is malformed")
		}
		if mappedInode != inode {
			continue
		}
		parts := strings.Split(fields[3], ":")
		if len(parts) != 2 {
			return 0, errors.New("managed process mapping device is malformed")
		}
		major, e1 := strconv.ParseUint(parts[0], 16, 32)
		minor, e2 := strconv.ParseUint(parts[1], 16, 32)
		if e1 != nil || e2 != nil {
			return 0, errors.New("managed process mapping device is malformed")
		}
		if major != uint64(unix.Major(device)) || minor != uint64(unix.Minor(device)) {
			continue
		}
		if !strings.HasPrefix(fields[1], "r") || strings.Contains(fields[1], "w") {
			return 0, errors.New("matching controlled source mapping is not readable and immutable")
		}
		bounds := strings.Split(fields[0], "-")
		if len(bounds) != 2 {
			return 0, errors.New("managed process mapping range is malformed")
		}
		start, e1 := strconv.ParseUint(bounds[0], 16, 64)
		end, e2 := strconv.ParseUint(bounds[1], 16, 64)
		offset, e3 := strconv.ParseUint(fields[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil || end <= start || offset > uint64(fileSize) {
			return 0, errors.New("managed process mapping range is invalid")
		}
		length := end - start
		if offset > ^uint64(0)-length {
			return 0, errors.New("managed process mapping source range overflows")
		}
		limit := offset + length
		if limit > uint64(fileSize) {
			limit = uint64(fileSize)
		}
		if limit > offset {
			segments = append(segments, checkpointMapSegment{start: offset, end: limit})
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].start < segments[j].start })
	var total, cursor uint64
	for _, segment := range segments {
		if segment.start > cursor {
			cursor = segment.start
		}
		if segment.end > cursor {
			total += segment.end - cursor
			cursor = segment.end
		}
	}
	return int64(total), nil
}

func checkpointVerifyModelMapped(ctx context.Context, mapsPath string, device, inode uint64, fileSize int64) (int64, error) {
	b, err := checkpointReadBounded(mapsPath, checkpointProcMaxRead)
	if err != nil {
		return 0, fmt.Errorf("read managed process mappings: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(b)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	segments := make([]checkpointMapSegment, 0, 8)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo%1024 == 0 {
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return 0, errors.New("managed process mapping table has a partial row")
		}
		mappedInode, err := strconv.ParseUint(fields[4], 10, 64)
		if err != nil {
			return 0, errors.New("managed process mapping inode is malformed")
		}
		if mappedInode != inode {
			continue
		}
		majorMinor := strings.Split(fields[3], ":")
		if len(majorMinor) != 2 {
			return 0, errors.New("managed process mapping device is malformed")
		}
		major, e1 := strconv.ParseUint(majorMinor[0], 16, 32)
		minor, e2 := strconv.ParseUint(majorMinor[1], 16, 32)
		if e1 != nil || e2 != nil {
			return 0, errors.New("managed process mapping device is malformed")
		}
		wantMajor, wantMinor := unix.Major(device), unix.Minor(device)
		if major != uint64(wantMajor) || minor != uint64(wantMinor) {
			continue
		}
		if fields[1] != "r--p" {
			return 0, errors.New("matching GGUF mapping is not readable, private, and non-writable")
		}
		bounds := strings.Split(fields[0], "-")
		if len(bounds) != 2 {
			return 0, errors.New("managed process mapping range is malformed")
		}
		start, e1 := strconv.ParseUint(bounds[0], 16, 64)
		end, e2 := strconv.ParseUint(bounds[1], 16, 64)
		offset, e3 := strconv.ParseUint(fields[2], 16, 64)
		if e1 != nil || e2 != nil || e3 != nil || end <= start {
			return 0, errors.New("managed process mapping range is malformed")
		}
		segments = append(segments, checkpointMapSegment{start: offset, end: offset + (end - start)})
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	if len(segments) == 0 {
		return 0, errors.New("configured GGUF inode is not mapped in the listener process")
	}
	sort.Slice(segments, func(i, j int) bool { return segments[i].start < segments[j].start })
	cursor := uint64(0)
	for _, segment := range segments {
		if segment.start > cursor {
			return 0, errors.New("observed GGUF mapping has a gap and cannot cover all source bytes")
		}
		if segment.end > cursor {
			cursor = segment.end
		}
	}
	if cursor < uint64(fileSize) {
		return 0, errors.New("observed GGUF mappings do not cover the complete artifact")
	}
	return fileSize, nil
}
