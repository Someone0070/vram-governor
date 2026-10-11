package nodeagent

import (
	"strings"
	"testing"
)

func checkpointPlacementFixture() CheckpointLaunchPlan {
	return CheckpointLaunchPlan{
		Version:            checkpointLaunchPlanVersion2,
		Alias:              "managed-model",
		Model:              CheckpointLaunchModel{Path: "/model", SHA256: strings.Repeat("a", 64), Bytes: 4096},
		Executable:         CheckpointLaunchExecutable{Path: "/server", SHA256: strings.Repeat("b", 64)},
		Endpoint:           CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080},
		TotalContextTokens: 4096,
		ParallelSlots:      4,
		SnapshotRoot:       "/snapshots",
		Custody:            CheckpointLaunchCustodyQuotas{Root: "/custody", MaxArtifactBytes: 4096, MaxStagingBytes: 8192, ReserveBytes: 4096},
		Placement: &CheckpointLaunchPlacement{
			Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef",
			RuntimeDeviceToken: "CUDA0", RuntimeVersion: "0.3.0-dev (build 1, commit 62acc89)", MaxAccelerators: 1,
			OffloadPolicy: "full_gpu", MinGPUBytes: 1 << 20, MaxHostRSSBytes: 8 << 30,
		},
	}
}

func TestCheckpointPlacementPlanBuildsOneDeviceInvocation(t *testing.T) {
	plan := checkpointPlacementFixture()
	args, err := fixedCheckpointPlacementArguments(plan)
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 23 || args[0] != "-m" || args[1] != "{CHECKPOINT_MODEL}" {
		t.Fatalf("unexpected one-device argv shape: %#v", args)
	}
	for _, required := range [][]string{{"--device", "CUDA0"}, {"--split-mode", "none"}, {"--main-gpu", "0"}, {"--n-gpu-layers", "all"}} {
		found := false
		for i := 0; i+1 < len(args); i++ {
			if args[i] == required[0] && args[i+1] == required[1] {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing internally fixed placement args %q: %#v", required, args)
		}
	}
	legacy := plan
	legacy.Version = checkpointLaunchPlanVersion
	if _, err := fixedCheckpointPlacementArguments(legacy); err == nil {
		t.Fatal("legacy v1 plan authorized new managed placement")
	}
}

func TestCheckpointPlacementRejectsUnsupportedCeilingAndPartialFallback(t *testing.T) {
	plan := checkpointPlacementFixture()
	plan.Placement.MaxAccelerators = 2
	if err := validateCheckpointLaunchPlacement(*plan.Placement); err == nil {
		t.Fatal("multi-accelerator placement ceiling was accepted")
	}
	plan = checkpointPlacementFixture()
	plan.Placement.OffloadPolicy = "partial_cpu"
	if _, err := fixedCheckpointPlacementArguments(plan); err == nil {
		t.Fatal("unsupported partial CPU offload silently became a managed launch")
	}
	plan = checkpointPlacementFixture()
	plan.Placement.RuntimeDeviceToken = "CUDA1"
	if err := validateCheckpointLaunchPlacement(*plan.Placement); err == nil {
		t.Fatal("unverified runtime device token was accepted")
	}
}

func TestCheckpointPlacementRequiresFreshMatchingPhysicalIdentity(t *testing.T) {
	plan := checkpointPlacementFixture()
	observation := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: "CUDA0", RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: "2026-10-01T00:00:00Z"}
	if err := validateCheckpointPlacementJoin(plan, observation); err != nil {
		t.Fatalf("matching local placement rejected: %v", err)
	}
	observation.PhysicalIdentity = "GPU-11111111-2222-3333-4444-555555555555"
	if err := validateCheckpointPlacementJoin(plan, observation); err == nil {
		t.Fatal("different physical device was accepted")
	}
}

func TestCheckpointOffloadEvidenceRequiresActualAllLayerPlacement(t *testing.T) {
	if err := validateCheckpointOffloadEvidence("full_gpu", checkpointOffloadEvidence{GPUBytes: 2 << 20, HostRSS: 1 << 30, LayersGPU: 33, LayersTotal: 33}, 1<<20, 8<<30); err != nil {
		t.Fatalf("positive measured full GPU evidence rejected: %v", err)
	}
	for _, evidence := range []checkpointOffloadEvidence{
		{GPUBytes: 2 << 20, HostRSS: 1 << 30, LayersGPU: 32, LayersTotal: 33},
		{GPUBytes: 1, HostRSS: 1 << 30, LayersGPU: 33, LayersTotal: 33},
		{GPUBytes: 2 << 20, HostRSS: 9 << 30, LayersGPU: 33, LayersTotal: 33},
	} {
		if err := validateCheckpointOffloadEvidence("full_gpu", evidence, 1<<20, 8<<30); err == nil {
			t.Fatalf("incomplete or out-of-plan measured footprint was accepted: %+v", evidence)
		}
	}
	if err := validateCheckpointOffloadEvidence("partial_cpu", checkpointOffloadEvidence{GPUBytes: 2 << 20, HostRSS: 1 << 30, LayersGPU: 16, LayersTotal: 33}, 1<<20, 8<<30); err == nil {
		t.Fatal("partial policy was treated as proven by aggregate footprints")
	}
}

func TestCheckpointOffloadLogRequiresOneCanonicalSummary(t *testing.T) {
	for _, raw := range []string{
		"load_tensors: offloaded 33/33 layers to GPU\n",
		"noise\nload_tensors: offloaded 33/32 layers to GPU\n",
		"load_tensors: offloaded 16/33 layers to GPU\nload_tensors: offloaded 33/33 layers to GPU\n",
		"load_tensors: offloaded 33/33 layers to GPU with fallback\n",
		"other_function: offloaded 33/33 layers to GPU\n",
	} {
		gpu, total, err := parseCheckpointOffloadLog(raw)
		if err == nil && raw != "load_tensors: offloaded 33/33 layers to GPU\n" {
			t.Fatalf("ambiguous or partial runtime log accepted: %q => %d/%d", raw, gpu, total)
		}
	}
	gpu, total, err := parseCheckpointOffloadLog("load_tensors: offloaded 33/33 layers to GPU\n")
	if err != nil || gpu != 33 || total != 33 {
		t.Fatalf("canonical all-layer runtime evidence failed: %d/%d %v", gpu, total, err)
	}
}

func TestCheckpointPlacementRuntimeVersionHasStrictBuildIdentity(t *testing.T) {
	good := "version: 0.3.0-dev (build 1, commit 62acc89)\nbuilt with GNU 13.3.0 for Linux x86_64\n"
	want := "0.3.0-dev (build 1, commit 62acc89), GNU 13.3.0 Linux x86_64"
	got, err := parseCheckpointLlamaVersionOutput(good)
	if err != nil || got != want {
		t.Fatalf("pinned build identity rejected: got=%q err=%v", got, err)
	}
	for _, raw := range []string{
		"version: 0.3.0-dev (build 1, commit 62acc88)\nbuilt with GNU 13.3.0 for Linux x86_64\n",
		good + "CUDA device initialized\n",
		"warning: version: 0.3.0-dev (build 1, commit 62acc89)\nbuilt with GNU 13.3.0 for Linux x86_64\n",
		"version: 0.3.0-dev (build 1, commit 62acc89)\nbuilt with GNU 13.3.0 for Linux x86_64\nbuilt with GNU 13.3.0 for Linux x86_64\n",
	} {
		if _, err := parseCheckpointLlamaVersionOutput(raw); err == nil {
			t.Fatalf("ambiguous or changed runtime build identity accepted: %q", raw)
		}
	}
}
