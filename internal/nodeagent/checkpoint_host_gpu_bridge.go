package nodeagent

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"vram-governor/internal/checkpointgpuobserver"
)

const (
	checkpointHostObserverSocket = checkpointgpuobserver.ObserverSocketPath
	checkpointNodeTrustPath      = "/etc/vram-governor/checkpoint-gpu-observer-node.json"
	checkpointNodePublicKeyPath  = "/etc/vram-governor/checkpoint-gpu-observer.pub"
)

type checkpointHostGPUObservation struct {
	Bytes    int64
	Response checkpointgpuobserver.Response
}

type checkpointHostGPUBridgeSource struct {
	observe func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (checkpointHostGPUObservation, error)
}

type checkpointHostGPUBridgeRuntimeConfig struct {
	socketPath      string
	trustPath       string
	publicKeyPath   string
	discoverDevices func(context.Context) ([]checkpointGPUDevice, error)
}

func observeCheckpointHostGPUAttribution(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {
	if ctx == nil || workerPID <= 1 || expectedStart == 0 || plan.Version != checkpointLaunchPlanVersion2 || plan.Placement == nil {
		return checkpointHostGPUObservation{}, errors.New("host GPU bridge request is incomplete")
	}
	role := checkpointHostGPUExpectedRole(os.Geteuid())
	return observeCheckpointHostGPUAttributionForRole(ctx, workerPID, expectedStart, plan, placement, role)
}

func checkpointHostGPUExpectedRole(euid int) string {
	if euid == 0 {
		return "fixed-supervisor"
	}
	return "node-agent"
}

func observeCheckpointHostGPUAttributionLocalObserver(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {
	if os.Geteuid() != 0 {
		return checkpointHostGPUObservation{}, errors.New("local-observer host bridge requires the fixed root collector")
	}
	return observeCheckpointHostGPUAttributionForRole(ctx, workerPID, expectedStart, plan, placement, "local-observer")
}

func observeCheckpointHostGPUAttributionForRole(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, role string) (checkpointHostGPUObservation, error) {
	if ctx == nil || workerPID <= 1 || expectedStart == 0 || plan.Version != checkpointLaunchPlanVersion2 || plan.Placement == nil ||
		(role != "node-agent" && role != "fixed-supervisor" && role != "local-observer") {
		return checkpointHostGPUObservation{}, errors.New("host GPU bridge request or fixed role is invalid")
	}
	if role == "local-observer" && os.Geteuid() != 0 || role == "node-agent" && os.Geteuid() == 0 {
		return checkpointHostGPUObservation{}, errors.New("host GPU bridge caller does not match the fixed role")
	}
	return observeCheckpointHostGPUAttributionPlatformForRole(ctx, workerPID, expectedStart, plan, placement, role)
}

func validateCheckpointHostGPUResponseRole(responseRole, expectedRole string) error {
	if (expectedRole != "node-agent" && expectedRole != "fixed-supervisor" && expectedRole != "local-observer") || responseRole != expectedRole {
		return errors.New("host observer signed a different caller role than the fixed route")
	}
	return nil
}

func validateCheckpointHostGPUObservation(observation checkpointHostGPUObservation, placement CheckpointDevicePlacement, plan CheckpointLaunchPlan) error {
	if observation.Bytes <= 0 || plan.Placement == nil || placement.Backend != plan.Placement.Backend ||
		observation.Response.GPU.Bytes != observation.Bytes || observation.Response.GPU.UUID != placement.ChildMaskUUID ||
		observation.Response.GPUUUID != placement.ChildMaskUUID || observation.Response.GPUPCI == "" ||
		plan.Placement.MaxAccelerators != 1 {
		return errors.New("host GPU bridge response does not match the fixed one-card placement")
	}
	if plan.Placement.IdentityKind == "pci_bus_id" && !strings.EqualFold(observation.Response.GPUPCI, plan.Placement.PhysicalIdentity) {
		return errors.New("host GPU bridge PCI identity differs from the pinned physical placement")
	}
	return nil
}

var checkpointHostGPUBridgeTimeout = 5 * time.Second
