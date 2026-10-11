//go:build linux

package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	checkpointNvidiaSMI               = "/usr/bin/nvidia-smi"
	checkpointProbeTimeout            = 3 * time.Second
	checkpointPlacementStartupTimeout = 5 * time.Second
	checkpointNSGetNSTYPE             = uintptr(0xb703)
	checkpointNSFSMagic               = uint64(0x6e736673)
	checkpointPIDNamespaceInitInode   = uint64(0xeffffffc)
	checkpointExecutableMaxBytes      = int64(1 << 30)
	checkpointExecutableReadChunk     = 64 << 10
)

var (
	errCheckpointExecutableColdCache         = errors.New("pinned runtime executable data is not immediately available for nonblocking verification")
	errCheckpointExecutableNowaitUnsupported = errors.New("pinned runtime filesystem does not support nonblocking executable verification")
)

func refreshCheckpointDevicePlacementPlatform(ctx context.Context, spec CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
	if spec.Version != checkpointLaunchPlanVersion2 || spec.Placement == nil || spec.Placement.Backend != "cuda" {
		return CheckpointDevicePlacement{}, errors.New("unsupported managed accelerator backend")
	}
	if spec.Placement == nil {
		return CheckpointDevicePlacement{}, errors.New("v2 placement object is required")
	}
	if err := validateCheckpointLaunchPlacement(*spec.Placement); err != nil {
		return CheckpointDevicePlacement{}, err
	}
	if spec.Placement.OffloadPolicy != "full_gpu" {
		return CheckpointDevicePlacement{}, errors.New("partial CPU offload is unsupported")
	}
	// The pinned digest and bounded --version output identify the executable,
	// not its dynamically loaded library bundle (including llama-server's
	// implementation library). Bundle provenance/compatibility must be bound
	// by later packaging/integration; this observation is not a permanent
	// runtime-library freeze or a standalone checkpoint-eligibility claim.
	if err := verifyCheckpointExecutableHash(ctx, spec.Executable.Path, spec.Executable.SHA256); err != nil {
		return CheckpointDevicePlacement{}, err
	}
	devices, err := discoverCheckpointNvidiaDevices(ctx)
	if err != nil {
		return CheckpointDevicePlacement{}, err
	}
	identityMatches := 0
	selectedUUID := ""
	for _, device := range devices {
		if spec.Placement.IdentityKind == "uuid" && device.UUID == spec.Placement.PhysicalIdentity || spec.Placement.IdentityKind == "pci_bus_id" && strings.EqualFold(device.PCI, spec.Placement.PhysicalIdentity) {
			identityMatches++
			selectedUUID = device.UUID
		}
	}
	if identityMatches != 1 {
		return CheckpointDevicePlacement{}, errors.New("pinned physical identity is absent or ambiguous in fresh CUDA inventory")
	}
	mask := runtimeCheckpointChildEnvironment(selectedUUID)
	version, err := runCheckpointBounded(ctx, spec.Executable.Path, []string{"--version"}, mask)
	parsedVersion, parseVersionErr := parseCheckpointLlamaVersionOutput(version)
	if err != nil || parseVersionErr != nil || parsedVersion != spec.Placement.RuntimeVersion {
		return CheckpointDevicePlacement{}, errors.New("pinned runtime version did not match fresh bounded version output")
	}
	help, err := runCheckpointBounded(ctx, spec.Executable.Path, []string{"--help"}, mask)
	if err != nil || !checkpointRuntimeSupportsPlacementFlags(help) {
		return CheckpointDevicePlacement{}, errors.New("pinned runtime help does not prove required one-device and full-offload flags")
	}
	listed, err := runCheckpointBounded(ctx, spec.Executable.Path, []string{"--list-devices"}, mask)
	if err != nil {
		return CheckpointDevicePlacement{}, errors.New("pinned runtime device listing failed under the child-equivalent physical-device mask")
	}
	if err := parseCheckpointRuntimeDeviceListing(listed, spec.Placement.RuntimeDeviceToken); err != nil {
		return CheckpointDevicePlacement{}, err
	}
	if err := verifyCheckpointExecutableHash(ctx, spec.Executable.Path, spec.Executable.SHA256); err != nil {
		return CheckpointDevicePlacement{}, err
	}
	return CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: spec.Placement.PhysicalIdentity, ChildMaskUUID: selectedUUID, RuntimeDeviceToken: spec.Placement.RuntimeDeviceToken, RuntimeVersion: spec.Placement.RuntimeVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}, nil
}

func discoverCheckpointNvidiaDevices(ctx context.Context) ([]checkpointGPUDevice, error) {
	raw, err := runCheckpointBounded(ctx, checkpointNvidiaSMI, []string{"--query-gpu=uuid,pci.bus_id", "--format=csv,noheader,nounits"}, []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"})
	if err != nil {
		return nil, fmt.Errorf("fresh NVIDIA physical inventory unavailable: %w", err)
	}
	var devices []checkpointGPUDevice
	seenUUID, seenPCI := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		parts := strings.Split(line, ",")
		if len(parts) != 2 {
			return nil, errors.New("NVIDIA physical inventory row is malformed")
		}
		uuid, pci := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if !checkpointGPUUUIDRE.MatchString(uuid) || !checkpointPCIBusIDRE.MatchString(pci) || seenUUID[uuid] || seenPCI[strings.ToLower(pci)] {
			return nil, errors.New("NVIDIA physical inventory contains malformed or duplicate identity")
		}
		seenUUID[uuid], seenPCI[strings.ToLower(pci)] = true, true
		devices = append(devices, checkpointGPUDevice{UUID: uuid, PCI: pci})
	}
	if len(devices) == 0 || len(devices) > 64 {
		return nil, errors.New("NVIDIA physical inventory is empty or exceeds the device bound")
	}
	return devices, nil
}

func runCheckpointBounded(parent context.Context, executable string, args, env []string) (string, error) {
	if parent == nil || executable == "" || len(args) == 0 || len(env) == 0 {
		return "", errors.New("bounded placement command is incomplete")
	}
	ctx, cancel := context.WithTimeout(parent, checkpointProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = append([]string(nil), env...)
	cmd.WaitDelay = time.Second
	bounded := &checkpointBoundedOutput{max: checkpointRuntimeOutputMax}
	cmd.Stdout, cmd.Stderr = bounded, bounded
	if err := cmd.Run(); err != nil {
		return "", err
	}
	return bounded.String()
}

type checkpointBoundedOutput struct {
	bytes.Buffer
	mu       sync.Mutex
	max      int
	overflow bool
}

func (b *checkpointBoundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.max - b.Len()
	if remaining <= 0 || len(p) > remaining {
		b.overflow = true
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

func (b *checkpointBoundedOutput) String() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.overflow {
		return "", errors.New("bounded command output exceeded maximum size")
	}
	return b.Buffer.String(), nil
}

func checkpointRuntimeSupportsPlacementFlags(help string) bool {
	for _, flag := range []string{"--device", "--split-mode", "--main-gpu", "--n-gpu-layers"} {
		if !strings.Contains(help, flag) {
			return false
		}
	}
	return true
}

func parseCheckpointRuntimeDeviceListing(raw, expectedToken string) error {
	if len(raw) == 0 || len(raw) > checkpointRuntimeOutputMax || expectedToken == "" {
		return errors.New("runtime device listing is empty, oversized, or unpinned")
	}
	var tokens []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefix, _, found := strings.Cut(line, ":")
		if !found || !regexpCheckpointRuntimeToken(prefix) {
			if strings.HasPrefix(line, "CUDA") || strings.HasPrefix(line, "HIP") || strings.HasPrefix(line, "Vulkan") || strings.HasPrefix(line, "Metal") {
				return errors.New("runtime device listing contains an unsupported or malformed accelerator token")
			}
			continue
		}
		tokens = append(tokens, prefix)
	}
	if len(tokens) != 1 || tokens[0] != expectedToken {
		return errors.New("runtime token association is absent, duplicated, reordered, or unexpected under the physical UUID mask")
	}
	return nil
}

func regexpCheckpointRuntimeToken(token string) bool { return token == "CUDA0" }

type checkpointRuntimeHealthState uint8

const (
	checkpointRuntimeHealthLoading checkpointRuntimeHealthState = iota + 1
	checkpointRuntimeHealthReady
)

func observeCheckpointRuntimeHealth(ctx context.Context, endpoint CheckpointLaunchEndpoint) (checkpointRuntimeHealthState, error) {
	if ctx == nil || endpoint.Host != "127.0.0.1" && endpoint.Host != "::1" || endpoint.Port < 1 || endpoint.Port > 65535 {
		return 0, errors.New("runtime health observation endpoint is invalid")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))+"/health", nil)
	if err != nil {
		return 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("pinned runtime health endpoint failed: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 16<<10+1))
	if err != nil || len(body) == 0 || len(body) > 16<<10 {
		return 0, errors.New("pinned runtime health response is empty or oversized")
	}
	if err := rejectCheckpointHealthJSONKeys(body, response.StatusCode == http.StatusServiceUnavailable); err != nil {
		return 0, errors.New("pinned runtime health response has unknown or noncanonical fields")
	}
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return 0, errors.New("pinned runtime health response is malformed")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if response.StatusCode == http.StatusServiceUnavailable {
		var loading struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Type    string `json:"type"`
			} `json:"error"`
		}
		if err := decoder.Decode(&loading); err != nil || loading.Error.Code != http.StatusServiceUnavailable || loading.Error.Message != "Loading model" || loading.Error.Type != "unavailable_error" {
			return 0, errors.New("pinned runtime health response is not the exact loading state")
		}
		if err := healthJSONEOF(decoder); err != nil {
			return 0, err
		}
		return checkpointRuntimeHealthLoading, nil
	}
	if response.StatusCode != http.StatusOK {
		return 0, errors.New("pinned runtime health endpoint returned a fatal or unexpected status")
	}
	var health struct {
		Status string `json:"status"`
	}
	if err := decoder.Decode(&health); err != nil || health.Status != "ok" {
		return 0, errors.New("pinned runtime health response does not report ready status")
	}
	if err := healthJSONEOF(decoder); err != nil {
		return 0, err
	}
	return checkpointRuntimeHealthReady, nil
}

func rejectCheckpointHealthJSONKeys(raw []byte, loading bool) error {
	root := map[string]struct{}{"status": {}}
	allowed := map[string]map[string]struct{}{"$": root}
	if loading {
		root = map[string]struct{}{"error": {}}
		allowed["$"] = root
		allowed["$.error"] = map[string]struct{}{"code": {}, "message": {}, "type": {}}
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	var walk func(string) error
	walk = func(objectPath string) error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			if token == nil {
				return fmt.Errorf("null field at %s", objectPath)
			}
			return nil
		}
		if delim != '{' {
			return fmt.Errorf("unexpected JSON container at %s", objectPath)
		}
		fields, known := allowed[objectPath]
		if !known {
			return fmt.Errorf("unexpected object at %s", objectPath)
		}
		seen := make(map[string]struct{}, len(fields))
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("health JSON key is not a string")
			}
			if _, ok := fields[key]; !ok {
				return fmt.Errorf("unknown or noncanonical health key %q at %s", key, objectPath)
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate health key %q at %s", key, objectPath)
			}
			seen[key] = struct{}{}
			if err := walk(objectPath + "." + key); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("malformed health object")
		}
		for key := range fields {
			if _, ok := seen[key]; !ok {
				return fmt.Errorf("missing health key %q at %s", key, objectPath)
			}
		}
		return nil
	}
	if err := walk("$"); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("health JSON contains trailing data")
	}
	return nil
}

func verifyCheckpointRuntimeHealth(ctx context.Context, endpoint CheckpointLaunchEndpoint) error {
	state, err := observeCheckpointRuntimeHealth(ctx, endpoint)
	if err != nil {
		return err
	}
	if state != checkpointRuntimeHealthReady {
		return errors.New("pinned runtime health endpoint returned loading after startup readiness")
	}
	return nil
}

func healthJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("pinned runtime health response contains trailing data")
	}
	return nil
}

func waitCheckpointRuntimeReady(ctx context.Context, endpoint CheckpointLaunchEndpoint, checkChild func(context.Context) error) error {
	if ctx == nil || checkChild == nil {
		return errors.New("runtime readiness wait requires bounded context and owned-child check")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := checkChild(ctx); err != nil {
			return fmt.Errorf("owned child changed while runtime was loading: %w", err)
		}
		state, err := observeCheckpointRuntimeHealth(ctx, endpoint)
		if err != nil {
			return err
		}
		if state == checkpointRuntimeHealthReady {
			return checkChild(ctx)
		}
		if state != checkpointRuntimeHealthLoading {
			return errors.New("pinned runtime health state is unsupported")
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func verifyCheckpointExecutableHash(ctx context.Context, path, expected string) error {
	if ctx == nil || path == "" || !checkpointLaunchSHA256RE.MatchString(expected) {
		return errors.New("pinned runtime executable hash is malformed")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointProbeTimeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size <= 0 || before.Size > checkpointExecutableMaxBytes {
		return errors.New("pinned runtime executable type or size is invalid")
	}
	digest, err := hashCheckpointExecutableFD(bounded, fd, before)
	if err != nil {
		return err
	}
	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return err
	}
	if !sameCheckpointExecutableStat(before, after) {
		return errors.New("pinned runtime executable identity or size changed during hashing")
	}
	if err := bounded.Err(); err != nil {
		return err
	}
	if !strings.EqualFold(fmt.Sprintf("%x", digest), expected) {
		return errors.New("pinned runtime executable bytes changed")
	}
	return nil
}

func hashCheckpointExecutableFD(ctx context.Context, fd int, initial unix.Stat_t) ([]byte, error) {
	h := sha256.New()
	buffer := make([]byte, checkpointExecutableReadChunk)
	offset := int64(0)
	for offset < initial.Size {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		want := int64(len(buffer))
		if remaining := initial.Size - offset; remaining < want {
			want = remaining
		}
		n, err := unix.Preadv2(fd, [][]byte{buffer[:int(want)]}, offset, unix.RWF_NOWAIT)
		if errors.Is(err, unix.EAGAIN) {
			return nil, errCheckpointExecutableColdCache
		}
		if errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) {
			return nil, errCheckpointExecutableNowaitUnsupported
		}
		if err != nil {
			return nil, err
		}
		if n <= 0 || int64(n) > want {
			return nil, errors.New("pinned runtime executable became short or malformed during nonblocking hashing")
		}
		_, _ = h.Write(buffer[:n])
		offset += int64(n)
	}
	return h.Sum(nil), nil
}

func sameCheckpointExecutableStat(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Size == after.Size && before.Mode == after.Mode && before.Nlink == after.Nlink && before.Uid == after.Uid && before.Gid == after.Gid && before.Ctim == after.Ctim
}

func observeCheckpointChildPlacement(ctx context.Context, spec CheckpointLaunchPlan, pid int, expectedStartTicks uint64, runtimeLog *checkpointRuntimeLog) (checkpointOffloadEvidence, error) {
	if runtimeLog == nil {
		return checkpointOffloadEvidence{}, errors.New("current child placement runtime evidence is unavailable")
	}
	source := checkpointChildPlacementSource{
		processStart: func(_ context.Context, workerPID int) (uint64, error) {
			return checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(workerPID)), workerPID)
		},
		pidNamespace:      verifyCheckpointDirectPIDNamespace,
		namespaceRoute:    checkpointWorkerUsesNestedPIDNamespace,
		nestedAttribution: observeCheckpointHostGPUAttribution,
		gpuProcesses: func(bounded context.Context) ([]checkpointGPUProcess, error) {
			return runCheckpointGPUProcessInventory(bounded)
		},
		devices: discoverCheckpointNvidiaDevices,
		hostRSS: readCheckpointProcessRSS,
		runtimeLog: func() ([]byte, error) {
			text, err := runtimeLog.snapshot()
			return []byte(text), err
		},
	}
	return observeCheckpointChildPlacementWithSource(ctx, spec, pid, expectedStartTicks, source)
}

func runCheckpointGPUProcessInventory(ctx context.Context) ([]checkpointGPUProcess, error) {
	if ctx == nil {
		return nil, errors.New("GPU process inventory context is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(bounded, checkpointNvidiaSMI, "--query-compute-apps=pid,gpu_uuid,used_gpu_memory", "--format=csv,noheader,nounits")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	cmd.WaitDelay = time.Second
	output := &checkpointBoundedOutput{max: checkpointRuntimeOutputMax}
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("fresh GPU process attribution failed: %w", err)
	}
	if _, err := observeCheckpointPIDNamespace(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "ns/pid")); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("nvidia-smi PID namespace is not anchored to the initial namespace: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("fresh GPU process attribution failed: %w", err)
	}
	rows, err := output.String()
	if err != nil {
		return nil, err
	}
	return parseCheckpointGPUProcesses(rows)
}

type checkpointChildPlacementSource struct {
	processStart      func(context.Context, int) (uint64, error)
	pidNamespace      func(context.Context, int) error
	namespaceRoute    func(context.Context, int) (bool, error)
	nestedAttribution func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (checkpointHostGPUObservation, error)
	gpuProcesses      func(context.Context) ([]checkpointGPUProcess, error)
	devices           func(context.Context) ([]checkpointGPUDevice, error)
	hostRSS           func(context.Context, int) (int64, error)
	runtimeLog        func() ([]byte, error)
}

func observeCheckpointChildPlacementWithSource(ctx context.Context, spec CheckpointLaunchPlan, pid int, expectedStartTicks uint64, source checkpointChildPlacementSource) (checkpointOffloadEvidence, error) {
	if ctx == nil || pid <= 1 || expectedStartTicks == 0 {
		return checkpointOffloadEvidence{}, errors.New("current child placement request is incomplete")
	}
	if spec.Version != checkpointLaunchPlanVersion2 || spec.Placement == nil {
		return checkpointOffloadEvidence{}, errors.New("current child placement requires a complete v2 placement plan")
	}
	if err := validateCheckpointLaunchPlacement(*spec.Placement); err != nil {
		return checkpointOffloadEvidence{}, err
	}
	if source.processStart == nil || source.pidNamespace == nil || source.namespaceRoute == nil || source.gpuProcesses == nil || source.devices == nil || source.hostRSS == nil || source.runtimeLog == nil {
		return checkpointOffloadEvidence{}, errors.New("current child placement evidence source is incomplete")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointPlacementStartupTimeout)
	defer cancel()
	start, err := source.processStart(bounded, pid)
	if err != nil || start != expectedStartTicks {
		return checkpointOffloadEvidence{}, errors.New("current child process incarnation changed before placement attribution")
	}
	nested, err := source.namespaceRoute(bounded, pid)
	if err != nil {
		return checkpointOffloadEvidence{}, fmt.Errorf("managed child namespace routing could not be established: %w", err)
	}
	if nested {
		if source.nestedAttribution == nil {
			return checkpointOffloadEvidence{}, errors.New("nested PID namespace host observer is unavailable")
		}
		devices, err := source.devices(bounded)
		if err != nil {
			return checkpointOffloadEvidence{}, err
		}
		expectedUUID := ""
		var selectedDevice *checkpointGPUDevice
		for index := range devices {
			match := spec.Placement.IdentityKind == "uuid" && devices[index].UUID == spec.Placement.PhysicalIdentity || spec.Placement.IdentityKind == "pci_bus_id" && strings.EqualFold(devices[index].PCI, spec.Placement.PhysicalIdentity)
			if match {
				if selectedDevice != nil {
					return checkpointOffloadEvidence{}, errors.New("pinned physical identity is ambiguous in nested observer preparation")
				}
				selectedDevice = &devices[index]
				expectedUUID = devices[index].UUID
			}
		}
		if selectedDevice == nil {
			return checkpointOffloadEvidence{}, errors.New("pinned physical identity is absent in nested observer preparation")
		}
		placement := CheckpointDevicePlacement{Backend: spec.Placement.Backend, PhysicalIdentity: spec.Placement.PhysicalIdentity, ChildMaskUUID: expectedUUID, RuntimeDeviceToken: spec.Placement.RuntimeDeviceToken, RuntimeVersion: spec.Placement.RuntimeVersion, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		observation, err := source.nestedAttribution(bounded, pid, expectedStartTicks, spec, placement)
		if err != nil {
			return checkpointOffloadEvidence{}, err
		}
		if err := validateCheckpointHostGPUObservation(observation, placement, spec); err != nil {
			return checkpointOffloadEvidence{}, err
		}
		hostRSS, err := source.hostRSS(bounded, pid)
		if err != nil {
			return checkpointOffloadEvidence{}, err
		}
		log, err := source.runtimeLog()
		if err != nil {
			return checkpointOffloadEvidence{}, err
		}
		gpuLayers, totalLayers, err := parseCheckpointOffloadLog(string(log))
		if err != nil {
			return checkpointOffloadEvidence{}, err
		}
		end, err := source.processStart(bounded, pid)
		if err != nil || end != expectedStartTicks {
			return checkpointOffloadEvidence{}, errors.New("nested managed child incarnation changed during host attribution")
		}
		evidence := checkpointOffloadEvidence{GPUBytes: observation.Bytes, HostRSS: hostRSS, LayersGPU: gpuLayers, LayersTotal: totalLayers}
		if err := validateCheckpointOffloadEvidence(spec.Placement.OffloadPolicy, evidence, spec.Placement.MinGPUBytes, spec.Placement.MaxHostRSSBytes); err != nil {
			return checkpointOffloadEvidence{}, err
		}
		return evidence, nil
	}
	if err := source.pidNamespace(bounded, pid); err != nil {
		return checkpointOffloadEvidence{}, err
	}
	processes, err := source.gpuProcesses(bounded)
	if err != nil {
		return checkpointOffloadEvidence{}, err
	}
	var selected *checkpointGPUProcess
	for index := range processes {
		if processes[index].PID == pid {
			if selected != nil {
				return checkpointOffloadEvidence{}, errors.New("current child is attributed to multiple accelerator rows")
			}
			selected = &processes[index]
		}
	}
	devices, err := source.devices(bounded)
	if err != nil {
		return checkpointOffloadEvidence{}, err
	}
	expectedUUID := ""
	for _, device := range devices {
		if spec.Placement.IdentityKind == "uuid" && device.UUID == spec.Placement.PhysicalIdentity || spec.Placement.IdentityKind == "pci_bus_id" && strings.EqualFold(device.PCI, spec.Placement.PhysicalIdentity) {
			if expectedUUID != "" {
				return checkpointOffloadEvidence{}, errors.New("pinned physical identity became ambiguous during child attribution")
			}
			expectedUUID = device.UUID
		}
	}
	if expectedUUID == "" || selected == nil || selected.UUID != expectedUUID || selected.UsedBytes <= 0 {
		return checkpointOffloadEvidence{}, errors.New("current child is absent from or outside the pinned physical GPU attribution")
	}
	hostRSS, err := source.hostRSS(bounded, pid)
	if err != nil {
		return checkpointOffloadEvidence{}, err
	}
	log, err := source.runtimeLog()
	if err != nil {
		return checkpointOffloadEvidence{}, err
	}
	gpuLayers, totalLayers, err := parseCheckpointOffloadLog(string(log))
	if err != nil {
		return checkpointOffloadEvidence{}, err
	}
	end, err := source.processStart(bounded, pid)
	if err != nil || end != expectedStartTicks {
		return checkpointOffloadEvidence{}, errors.New("current child process incarnation changed during placement attribution")
	}
	evidence := checkpointOffloadEvidence{GPUBytes: selected.UsedBytes, HostRSS: hostRSS, LayersGPU: gpuLayers, LayersTotal: totalLayers}
	if err := validateCheckpointOffloadEvidence(spec.Placement.OffloadPolicy, evidence, spec.Placement.MinGPUBytes, spec.Placement.MaxHostRSSBytes); err != nil {
		return checkpointOffloadEvidence{}, err
	}
	return evidence, nil
}

func verifyCheckpointDirectPIDNamespace(ctx context.Context, pid int) error {
	raw, err := checkpointReadBounded(filepath.Join("/proc", strconv.Itoa(pid), "status"), 64<<10)
	if err != nil {
		return err
	}
	chain, err := parseCheckpointPIDNamespaceChain(string(raw), pid)
	if err != nil {
		return err
	}
	if err := checkpointPIDNamespaceChainIsConsistent(chain); err != nil {
		return err
	}
	observer, err := observeCheckpointPIDNamespace("/proc/self/ns/pid")
	if err != nil {
		return fmt.Errorf("observer PID namespace is not anchored to the initial namespace: %w", err)
	}
	child, err := observeCheckpointPIDNamespace(filepath.Join("/proc", strconv.Itoa(pid), "ns/pid"))
	if err != nil {
		return fmt.Errorf("managed child PID namespace is not anchored to the initial namespace: %w", err)
	}
	if observer != child {
		return errors.New("observer and managed child do not share the anchored initial PID namespace")
	}
	return nil
}

type checkpointPIDNamespaceIdentity struct {
	Device uint64
	Inode  uint64
}

func observeCheckpointPIDNamespace(path string) (checkpointPIDNamespaceIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return checkpointPIDNamespaceIdentity{}, err
	}
	defer file.Close()

	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return checkpointPIDNamespaceIdentity{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(file.Fd()), &fs); err != nil {
		return checkpointPIDNamespaceIdentity{}, err
	}
	namespaceType, _, errno := unix.Syscall(unix.SYS_IOCTL, file.Fd(), checkpointNSGetNSTYPE, 0)
	if errno != 0 {
		return checkpointPIDNamespaceIdentity{}, errno
	}
	identity := checkpointPIDNamespaceIdentity{Device: uint64(stat.Dev), Inode: stat.Ino}
	if err := validateCheckpointInitialPIDNamespace(uint64(fs.Type), uint64(namespaceType), identity.Inode); err != nil {
		return checkpointPIDNamespaceIdentity{}, err
	}
	return identity, nil
}

func validateCheckpointInitialPIDNamespace(filesystemType, namespaceType, inode uint64) error {
	// Linux UAPI reserves PID_NS_INIT_INO (0xEFFFFFFC) for init_pid_ns;
	// proc namespace allocators use dynamic inodes from 0xF0000000 upward.
	// Require all three held-FD observations, and fail closed if a kernel does
	// not implement this ABI/rule. This is an inode anchor, not an NSpid or
	// container-environment heuristic.
	if filesystemType != checkpointNSFSMagic || namespaceType != uint64(unix.CLONE_NEWPID) || inode != checkpointPIDNamespaceInitInode {
		return errors.New("PID namespace descriptor is not the anchored Linux initial PID namespace")
	}
	return nil
}

func checkpointPIDNamespaceChainIsConsistent(chain []int) error {
	if len(chain) == 0 {
		return errors.New("GPU process PID namespace evidence is absent")
	}
	return nil
}

func parseCheckpointPIDNamespaceChain(raw string, expectedPID int) ([]int, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || expectedPID <= 1 {
		return nil, errors.New("process PID namespace evidence is empty or outside bounds")
	}
	var chain []int
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 256), 4096)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "NSpid:") {
			continue
		}
		if found {
			return nil, errors.New("process status contains duplicate PID namespace chains")
		}
		found = true
		for _, field := range strings.Fields(strings.TrimPrefix(line, "NSpid:")) {
			value, parseErr := strconv.Atoi(field)
			if parseErr != nil || value <= 1 || len(chain) >= 32 {
				return nil, errors.New("process PID namespace chain is malformed or oversized")
			}
			chain = append(chain, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !found || len(chain) == 0 || chain[len(chain)-1] != expectedPID {
		return nil, errors.New("process PID namespace chain is absent or does not end in the current process PID")
	}
	seen := map[int]bool{}
	for _, value := range chain {
		if seen[value] {
			return nil, errors.New("process PID namespace chain contains ambiguous repeated identifiers")
		}
		seen[value] = true
	}
	return chain, nil
}

func parseCheckpointGPUProcesses(raw string) ([]checkpointGPUProcess, error) {
	if len(raw) > checkpointRuntimeOutputMax {
		return nil, errors.New("GPU process inventory exceeded output bound")
	}
	var processes []checkpointGPUProcess
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 3 {
			return nil, errors.New("GPU process inventory row is malformed")
		}
		pid, errPID := strconv.Atoi(strings.TrimSpace(parts[0]))
		uuid := strings.TrimSpace(parts[1])
		mib, errMemory := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if errPID != nil || pid <= 1 || !checkpointGPUUUIDRE.MatchString(uuid) || errMemory != nil || mib <= 0 || mib > (1<<50)/(1<<20) {
			return nil, errors.New("GPU process inventory contains malformed identity or footprint")
		}
		processes = append(processes, checkpointGPUProcess{PID: pid, UUID: uuid, UsedBytes: mib << 20})
	}
	return processes, nil
}

func readCheckpointProcessRSS(ctx context.Context, pid int) (int64, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "smaps_rollup"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, 64<<10))
	var rss int64
	for {
		line, readErr := reader.ReadString('\n')
		if len(line) > 4096 {
			return 0, errors.New("process memory footprint line exceeded bound")
		}
		if strings.HasPrefix(line, "Rss:") {
			if rss != 0 {
				return 0, errors.New("process memory footprint has duplicate RSS")
			}
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[2] != "kB" {
				return 0, errors.New("process memory footprint RSS is malformed")
			}
			kib, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr != nil || kib <= 0 || kib > (1<<50)/1024 {
				return 0, errors.New("process memory footprint RSS is outside bounds")
			}
			rss = kib << 10
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, readErr
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	if rss == 0 {
		return 0, errors.New("process memory footprint RSS is absent")
	}
	return rss, nil
}
