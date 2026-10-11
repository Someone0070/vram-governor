package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

var (
	checkpointGPUUUIDRE            = regexp.MustCompile(`^GPU-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	checkpointPCIBusIDRE           = regexp.MustCompile(`^(?:[0-9A-Fa-f]{4}|[0-9A-Fa-f]{8}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$`)
	checkpointLlamaVersionOutputRE = regexp.MustCompile(`^version: ([A-Za-z0-9.+_-]+) \(build ([0-9]{1,10}), commit ([0-9a-f]{7,40})\)\nbuilt with ([A-Za-z0-9.+_-]+(?: [A-Za-z0-9.+_-]+)*) for ([A-Za-z0-9._-]+(?: [A-Za-z0-9._-]+)*)\n?$`)
)

const checkpointRuntimeOutputMax = 256 << 10

// CheckpointDevicePlacement is a fresh local observation for diagnostics and
// later capability integration. It is not itself a capability proof.
type CheckpointDevicePlacement struct {
	Backend            string
	PhysicalIdentity   string
	ChildMaskUUID      string
	RuntimeDeviceToken string
	RuntimeVersion     string
	ObservedAt         string
}

type checkpointGPUDevice struct {
	UUID string
	PCI  string
}

type checkpointGPUProcess struct {
	PID       int
	UUID      string
	UsedBytes int64
}

// RefreshCheckpointDevicePlacement performs a bounded, current local CUDA
// discovery for the fixed managed plan. It does not start a model or issue
// capability; unsupported platforms and ambiguous observations fail closed.
func RefreshCheckpointDevicePlacement(ctx context.Context, planPath string) (CheckpointDevicePlacement, error) {
	if ctx == nil {
		return CheckpointDevicePlacement{}, errors.New("placement refresh context is required")
	}
	plan, err := OpenCheckpointLaunchPlan(ctx, planPath)
	if err != nil {
		return CheckpointDevicePlacement{}, err
	}
	defer plan.Close()
	spec := plan.Spec()
	if spec.Version != checkpointLaunchPlanVersion2 {
		return CheckpointDevicePlacement{}, errors.New("legacy v1 plan cannot authorize managed placement")
	}
	return refreshCheckpointDevicePlacementPlatform(ctx, spec)
}

func validateCheckpointPlacementJoin(spec CheckpointLaunchPlan, observation CheckpointDevicePlacement) error {
	if spec.Version != checkpointLaunchPlanVersion2 || spec.Placement == nil || spec.Placement.MaxAccelerators != 1 {
		return errors.New("managed placement plan is unsupported")
	}
	if observation.Backend != spec.Placement.Backend || observation.PhysicalIdentity != spec.Placement.PhysicalIdentity || !checkpointGPUUUIDRE.MatchString(observation.ChildMaskUUID) || observation.RuntimeDeviceToken != spec.Placement.RuntimeDeviceToken || observation.RuntimeVersion != spec.Placement.RuntimeVersion || observation.ObservedAt == "" {
		return errors.New("fresh physical device association does not match the pinned placement")
	}
	return nil
}

func runtimeCheckpointChildEnvironment(physicalIdentity string) []string {
	return []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent", "CUDA_DEVICE_ORDER=PCI_BUS_ID", "CUDA_VISIBLE_DEVICES=" + physicalIdentity}
}

// checkpointRuntimeLog is attached only to the owned child stdout/stderr. It
// retains a small fixed prefix, records truncation, and never blocks startup.
type checkpointRuntimeLog struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (l *checkpointRuntimeLog) Write(p []byte) (int, error) {
	if l == nil {
		return len(p), nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	remaining := checkpointRuntimeOutputMax - len(l.data)
	if remaining <= 0 || len(p) > remaining {
		l.overflow = true
		if remaining > 0 {
			l.data = append(l.data, p[:remaining]...)
		}
		return len(p), nil
	}
	l.data = append(l.data, p...)
	return len(p), nil
}

func (l *checkpointRuntimeLog) snapshot() (string, error) {
	if l == nil {
		return "", errors.New("runtime output evidence is unavailable")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.overflow {
		return "", errors.New("runtime output exceeded evidence bound")
	}
	return string(append([]byte(nil), l.data...)), nil
}

type checkpointOffloadEvidence struct {
	GPUBytes    int64
	HostRSS     int64
	LayersGPU   int
	LayersTotal int
}

func validateCheckpointOffloadEvidence(policy string, evidence checkpointOffloadEvidence, minGPUBytes, maxHostRSSBytes int64) error {
	if policy != "full_gpu" {
		return errors.New("partial CPU offload is unsupported until actual layer placement is independently observable")
	}
	if evidence.GPUBytes < minGPUBytes || evidence.HostRSS <= 0 || evidence.HostRSS > maxHostRSSBytes {
		return fmt.Errorf("measured GPU/host footprint is outside the pinned plan bounds")
	}
	if evidence.LayersTotal <= 0 || evidence.LayersGPU != evidence.LayersTotal {
		return errors.New("runtime did not provide bounded evidence that every offloadable layer was assigned to the selected GPU")
	}
	return nil
}

func parseCheckpointLlamaVersionOutput(raw string) (string, error) {
	if len(raw) == 0 || len(raw) > 4096 || strings.ContainsAny(raw, "\x00\r") {
		return "", errors.New("pinned runtime version output is empty, oversized, or malformed")
	}
	match := checkpointLlamaVersionOutputRE.FindStringSubmatch(raw)
	if len(match) != 6 || match[3] != "62acc89" {
		return "", errors.New("pinned runtime version output does not match the reviewed llama.cpp build format and commit")
	}
	return fmt.Sprintf("%s (build %s, commit %s), %s %s", match[1], match[2], match[3], match[4], match[5]), nil
}

func parseCheckpointOffloadLog(raw string) (gpu, total int, err error) {
	// llama.cpp 62acc89 logs its all-offloadable-layer count before tensor-data
	// loading. It is not evidence that all weights are on GPU or that startup
	// completed; callers must separately join healthy service and child identity.
	var found int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "offloaded ") || !strings.Contains(line, " layers to GPU") {
			continue
		}
		var a, b int
		if n, _ := fmt.Sscanf(line, "load_tensors: offloaded %d/%d layers to GPU", &a, &b); n != 2 || a < 0 || b <= 0 || a > b {
			return 0, 0, errors.New("runtime layer placement summary is malformed")
		}
		if fmt.Sprintf("load_tensors: offloaded %d/%d layers to GPU", a, b) != line {
			return 0, 0, errors.New("runtime layer placement summary is noncanonical")
		}
		gpu, total = a, b
		found++
	}
	if found != 1 {
		return 0, 0, errors.New("runtime layer placement summary is absent or ambiguous")
	}
	return gpu, total, nil
}
