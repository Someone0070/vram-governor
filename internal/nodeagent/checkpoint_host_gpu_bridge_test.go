package nodeagent

import (
	"testing"

	"vram-governor/internal/checkpointgpuobserver"
)

func TestCheckpointHostGPUObservationRequiresExactPinnedPhysicalPlacement(t *testing.T) {
	plan := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-00000000-0000-0000-0000-000000000001", MaxAccelerators: 1}}
	placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity}
	valid := checkpointHostGPUObservation{Bytes: 2 << 20, Response: checkpointgpuobserver.Response{GPU: checkpointgpuobserver.GPUProcess{PID: 42, UUID: placement.ChildMaskUUID, Bytes: 2 << 20}, GPUUUID: placement.ChildMaskUUID, GPUPCI: "0000:01:00.0"}}
	if err := validateCheckpointHostGPUObservation(valid, placement, plan); err != nil {
		t.Fatalf("valid one-card host observation rejected: %v", err)
	}
	for name, mutate := range map[string]func(*checkpointHostGPUObservation){
		"missing bytes":        func(observation *checkpointHostGPUObservation) { observation.Bytes = 0 },
		"wrong response bytes": func(observation *checkpointHostGPUObservation) { observation.Response.GPU.Bytes++ },
		"wrong process UUID": func(observation *checkpointHostGPUObservation) {
			observation.Response.GPU.UUID = "GPU-00000000-0000-0000-0000-000000000099"
		},
		"wrong plan UUID": func(observation *checkpointHostGPUObservation) {
			observation.Response.GPUUUID = "GPU-00000000-0000-0000-0000-000000000099"
		},
		"missing PCI": func(observation *checkpointHostGPUObservation) { observation.Response.GPUPCI = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := valid
			changed.Response = valid.Response
			mutate(&changed)
			if err := validateCheckpointHostGPUObservation(changed, placement, plan); err == nil {
				t.Fatal("unjoined physical observation was accepted")
			}
		})
	}
}

func TestCheckpointHostGPUObservationBindsPlannedPCIBus(t *testing.T) {
	plan := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion2, Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "pci_bus_id", PhysicalIdentity: "0000:01:00.0", MaxAccelerators: 1}}
	placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: "GPU-00000000-0000-0000-0000-000000000001"}
	observation := checkpointHostGPUObservation{Bytes: 1, Response: checkpointgpuobserver.Response{GPU: checkpointgpuobserver.GPUProcess{PID: 42, UUID: placement.ChildMaskUUID, Bytes: 1}, GPUUUID: placement.ChildMaskUUID, GPUPCI: "0000:01:00.0"}}
	if err := validateCheckpointHostGPUObservation(observation, placement, plan); err != nil {
		t.Fatalf("case-insensitive pinned PCI identity rejected: %v", err)
	}
	observation.Response.GPUPCI = "0000:02:00.0"
	if err := validateCheckpointHostGPUObservation(observation, placement, plan); err == nil {
		t.Fatal("different planned physical PCI device was accepted")
	}
}
