//go:build linux

package nodeagent

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"
)

func managedBindingFixture() (CheckpointLaunchPlan, CheckpointVerifiedUnitAssociation) {
	plan := CheckpointLaunchPlan{
		Version: checkpointLaunchPlanVersion2, Alias: "resident-a",
		Model:              CheckpointLaunchModel{Path: "/approved/model.gguf", SHA256: fmt.Sprintf("%064x", 1), Bytes: 1024},
		Executable:         CheckpointLaunchExecutable{Path: "/approved/llama-server", SHA256: fmt.Sprintf("%064x", 2)},
		Endpoint:           CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080},
		TotalContextTokens: 4096, ParallelSlots: 2, SnapshotRoot: "/snapshots",
		Custody:   CheckpointLaunchCustodyQuotas{Root: checkpointFixedCustodyRoot, MaxArtifactBytes: 2048, MaxStagingBytes: 4096},
		Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-00000000-0000-0000-0000-000000000001", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "llama.cpp (build 123, commit 62acc89), CUDA test", MaxAccelerators: 1, OffloadPolicy: "full_gpu", MinGPUBytes: 1 << 20, MaxHostRSSBytes: 1 << 40},
	}
	association := CheckpointVerifiedUnitAssociation{
		Invocation: "0123456789abcdef0123456789abcdef", ControlGroup: "/system.slice/llama-server.service",
		Custody:  CheckpointCustodyVerification{EvidenceKind: "controlled-source-fs-verity-v2", ModelArgument: "/proc/self/fd/4", ArgvSHA256: fmt.Sprintf("%064x", 3), BindingSHA256: fmt.Sprintf("%064x", 4), Nonce: fmt.Sprintf("%064x", 5), Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified", BootID: "00000000-0000-0000-0000-000000000001", PID: 42, ProcessStartTicks: 77, ListenerSocketInode: 91, ActualAlias: "resident-a", ArtifactPath: "/var/lib/vram-governor/checkpoint-custody/models/model.gguf", ArtifactSize: 1024, ArtifactSHA256: fmt.Sprintf("%064x", 1), ExecutablePath: "/var/lib/vram-governor/checkpoint-custody/launchers/server", ExecutableSHA256: fmt.Sprintf("%064x", 2)},
		Identity: CheckpointLocalIdentity{EvidenceKind: "controlled-source-fs-verity-v2", Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit, BootID: "00000000-0000-0000-0000-000000000001", PID: 42, ProcessStartTicks: 77, ListenerIP: "127.0.0.1", ListenerPort: 8080, ListenerSocketInode: 91, ExecutablePath: "/var/lib/vram-governor/checkpoint-custody/launchers/server", ExecutableSHA256: fmt.Sprintf("%064x", 2), ExecutableDevice: 8, ExecutableInode: 20, ExecutableSize: 4096, ModelPath: "/var/lib/vram-governor/checkpoint-custody/models/model.gguf", ModelSHA256: fmt.Sprintf("%064x", 1), ModelDevice: 8, ModelInode: 21, ModelSize: 1024, ObservedMappedBytes: 512, Fingerprint: "measurement-is-not-incarnation"},
	}
	return plan, association
}

func managedBindingTestSource(plan CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) (checkpointManagedObservationSource, *int, *int) {
	associationCalls := 0
	recheckCalls := 0
	pin := &PinnedCheckpointLaunchPlan{plan: plan, contentSHA256: sha256.Sum256([]byte("pinned test plan"))}
	placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: "measurement timestamp"}
	source := checkpointManagedObservationSource{
		openPlan:     func(context.Context) (*PinnedCheckpointLaunchPlan, error) { return pin, nil },
		validatePlan: func(pinned *PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error) { return pinned.Spec(), nil },
		recheckPlan:  func(context.Context, *PinnedCheckpointLaunchPlan) error { recheckCalls++; return nil },
		openStore:    func(CheckpointLaunchPlan) (*CheckpointCustodyStore, error) { return &CheckpointCustodyStore{}, nil },
		associate: func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
			associationCalls++
			return association, nil
		},
		alias:          func(context.Context, CheckpointLaunchEndpoint, string) (string, error) { return plan.Alias, nil },
		placement:      func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) { return placement, nil },
		namespaceRoute: func(context.Context, int) (bool, error) { return false, nil },
		footprint: func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) {
			return 2 << 20, 8 << 20, nil
		},
		readArgv: func(int) ([]string, error) { return managedCheckpointExpectedArgv(plan) },
	}
	return source, &associationCalls, &recheckCalls
}

func TestCheckpointManagedBindingNestedObserverRouteAndNoFallback(t *testing.T) {
	plan, association := managedBindingFixture()
	source, _, _ := managedBindingTestSource(plan, association)
	source.namespaceRoute = func(context.Context, int) (bool, error) { return true, nil }
	directCalls, nestedCalls := 0, 0
	source.footprint = func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) {
		directCalls++
		return 2 << 20, 8 << 20, nil
	}
	source.nestedFootprint = func(_ context.Context, pid int, start uint64, gotPlan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (int64, int64, error) {
		nestedCalls++
		if pid != association.Identity.PID || start != association.Identity.ProcessStartTicks || gotPlan.Alias != plan.Alias || placement.ChildMaskUUID != plan.Placement.PhysicalIdentity {
			t.Fatal("nested adapter did not receive the exact owned process and pinned placement")
		}
		return 2 << 20, 8 << 20, nil
	}
	if _, err := observeCheckpointManagedBindingLinux(context.Background(), source); err != nil {
		t.Fatal(err)
	}
	if directCalls != 0 || nestedCalls != 1 {
		t.Fatalf("nested/direct observer calls = %d/%d", nestedCalls, directCalls)
	}
	source.nestedFootprint = func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error) {
		nestedCalls++
		return 0, 0, errors.New("host bridge unavailable")
	}
	if _, err := observeCheckpointManagedBindingLinux(context.Background(), source); err == nil || directCalls != 0 {
		t.Fatal("bridge failure fell back to direct host attribution")
	}
}

func TestCheckpointManagedBindingObserverRoleRouting(t *testing.T) {
	var localCalls, rootCalls int
	want := CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, CurrentIncarnation: "signed-local-binding"}
	got, err := routeCheckpointManagedBindingObserver(context.Background(), 65534, func(context.Context) (CheckpointManagedBinding, error) {
		localCalls++
		return want, nil
	}, func(context.Context) (CheckpointManagedBinding, error) {
		rootCalls++
		return CheckpointManagedBinding{}, nil
	})
	if err != nil || got.CurrentIncarnation != want.CurrentIncarnation || localCalls != 1 || rootCalls != 0 {
		t.Fatalf("nonroot did not use exactly the signed local route: got=%+v local=%d root=%d err=%v", got, localCalls, rootCalls, err)
	}
	for name, failure := range map[string]func(context.Context) error{
		"canceled": func(ctx context.Context) error { return ctx.Err() },
		"deadline": func(ctx context.Context) error { return ctx.Err() },
		"key unavailable": func(context.Context) error { return errors.New("pinned observer key unavailable") },
		"socket unavailable": func(context.Context) error { return errors.New("fixed observer socket unavailable") },
		"stale response": func(context.Context) error { return errors.New("signed observer response is stale") },
		"signature invalid": func(context.Context) error { return errors.New("observer response signature is invalid") },
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			if name == "canceled" {
				var stop context.CancelFunc
				ctx, stop = context.WithCancel(ctx)
				stop()
			} else if name == "deadline" {
				var stop context.CancelFunc
				ctx, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				cancel = stop
			}
			defer cancel()
			beforeLocal, beforeRoot := localCalls, rootCalls
			got, err := routeCheckpointManagedBindingObserver(ctx, 65534, func(callCtx context.Context) (CheckpointManagedBinding, error) {
				localCalls++
				return want, failure(callCtx)
			}, func(context.Context) (CheckpointManagedBinding, error) {
				rootCalls++
				return want, nil
			})
			if err == nil || got.Version != "" || got.CurrentIncarnation != "" || got.GPUBytes != 0 || got.HostRSSBytes != 0 || localCalls != beforeLocal+1 || rootCalls != beforeRoot {
				t.Fatalf("local %s error fell back or leaked a binding: got=%+v local=%d root=%d err=%v", name, got, localCalls, rootCalls, err)
			}
		})
	}
	localCallsBeforeRoot := localCalls
	got, err = routeCheckpointManagedBindingObserver(context.Background(), 0, func(context.Context) (CheckpointManagedBinding, error) {
		localCalls++
		return want, nil
	}, func(context.Context) (CheckpointManagedBinding, error) {
		rootCalls++
		return want, nil
	})
	if err != nil || got.CurrentIncarnation != want.CurrentIncarnation || rootCalls != 1 || localCalls != localCallsBeforeRoot {
		t.Fatalf("root did not preserve the direct collector route: got=%+v local=%d root=%d err=%v", got, localCalls, rootCalls, err)
	}
}

func TestCheckpointManagedBindingOrchestrationPositive(t *testing.T) {
	plan, association := managedBindingFixture()
	source, associationCalls, recheckCalls := managedBindingTestSource(plan, association)
	got, err := observeCheckpointManagedBindingLinux(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != checkpointLaunchPlanVersion2 || got.CurrentIncarnation == "" || got.Alias != plan.Alias || got.GPUBytes != 2<<20 || got.HostRSSBytes != 8<<20 {
		t.Fatalf("unexpected bounded managed observation: %#v", got)
	}
	if *associationCalls != 2 || *recheckCalls != 2 {
		t.Fatalf("association/recheck samples = %d/%d, want 2/2", *associationCalls, *recheckCalls)
	}
}

func TestCheckpointManagedBindingOrchestrationFaultControls(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*checkpointManagedObservationSource, CheckpointLaunchPlan, CheckpointVerifiedUnitAssociation)
	}{
		{name: "staged artifact mismatch", mutate: func(source *checkpointManagedObservationSource, plan CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			association.Custody.ArtifactSHA256 = fmt.Sprintf("%064x", 99)
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				return association, nil
			}
		}},
		{name: "argv0 staged path confusion", mutate: func(source *checkpointManagedObservationSource, plan CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.readArgv = func(int) ([]string, error) {
				calls++
				argv, _ := managedCheckpointExpectedArgv(plan)
				if calls == 1 {
					argv[0] = "/staged/server"
				}
				return argv, nil
			}
		}},
		{name: "context changed", mutate: func(source *checkpointManagedObservationSource, plan CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			source.readArgv = func(int) ([]string, error) {
				argv, _ := managedCheckpointExpectedArgv(plan)
				argv[11] = "8192"
				return argv, nil
			}
		}},
		{name: "ambiguous current alias", mutate: func(source *checkpointManagedObservationSource, plan CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.alias = func(context.Context, CheckpointLaunchEndpoint, string) (string, error) {
				calls++
				if calls == 1 {
					return plan.Alias, nil
				}
				return "other", nil
			}
		}},
		{name: "wrong initial current alias", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			source.alias = func(context.Context, CheckpointLaunchEndpoint, string) (string, error) { return "other", nil }
		}},
		{name: "physical footprint outside plan", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			source.footprint = func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) {
				return 1, 8 << 20, nil
			}
		}},
		{name: "missing physical attribution", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			source.footprint = func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) {
				return 0, 0, errors.New("target process absent")
			}
		}},
		{name: "plan substitution at final recheck", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, _ CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.recheckPlan = func(context.Context, *PinnedCheckpointLaunchPlan) error {
				calls++
				if calls == 2 {
					return errors.New("pinned plan changed")
				}
				return nil
			}
		}},
		{name: "process incarnation changed", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				calls++
				result := association
				if calls == 2 {
					result.Identity.PID++
				}
				return result, nil
			}
		}},
		{name: "start ticks changed", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				calls++
				result := association
				if calls == 2 {
					result.Identity.ProcessStartTicks++
				}
				return result, nil
			}
		}},
		{name: "listener socket changed", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				calls++
				result := association
				if calls == 2 {
					result.Identity.ListenerSocketInode++
				}
				return result, nil
			}
		}},
		{name: "unit invocation changed", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				calls++
				result := association
				if calls == 2 {
					result.Invocation = "abcdef0123456789abcdef0123456789"
				}
				return result, nil
			}
		}},
		{name: "unit cgroup changed", mutate: func(source *checkpointManagedObservationSource, _ CheckpointLaunchPlan, association CheckpointVerifiedUnitAssociation) {
			calls := 0
			source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
				calls++
				result := association
				if calls == 2 {
					result.ControlGroup = "/system.slice/other.service"
				}
				return result, nil
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, association := managedBindingFixture()
			source, _, _ := managedBindingTestSource(plan, association)
			test.mutate(&source, plan, association)
			if _, err := observeCheckpointManagedBindingLinux(context.Background(), source); err == nil {
				t.Fatal("managed association fault was accepted")
			}
		})
	}
}

func TestCheckpointManagedBindingObservationFreshness(t *testing.T) {
	plan, association := managedBindingFixture()
	source, _, _ := managedBindingTestSource(plan, association)
	calls := 0
	source.associate = func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
		calls++
		result := association
		result.Identity.ObservedMappedBytes = int64(calls * 111)
		result.Identity.Fingerprint = fmt.Sprintf("measured-%d", calls)
		return result, nil
	}
	placementCalls := 0
	source.placement = func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
		placementCalls++
		placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: fmt.Sprintf("sample-%d", placementCalls)}
		return placement, nil
	}
	got, err := observeCheckpointManagedBindingLinux(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	reference := managedCheckpointCurrentIncarnation(association, plan, mustManagedArgv(t, plan))
	secondSource, _, _ := managedBindingTestSource(plan, association)
	secondSource.placement = func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
		return CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken, RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: "a different timestamp"}, nil
	}
	secondSource.footprint = func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error) {
		return 4 << 20, 16 << 20, nil
	}
	secondObservation, secondErr := observeCheckpointManagedBindingLinux(context.Background(), secondSource)
	if secondErr != nil {
		t.Fatal(secondErr)
	}
	if got.CurrentIncarnation != reference || secondObservation.CurrentIncarnation != got.CurrentIncarnation || calls != 2 || placementCalls != 1 {
		t.Fatal("changing mapped-byte, measurement fingerprint, or observation timestamps altered the stable current association")
	}
}

func TestCheckpointManagedBindingAssociationTupleControls(t *testing.T) {
	_, base := managedBindingFixture()
	mutations := []struct {
		name   string
		mutate func(*CheckpointVerifiedUnitAssociation)
	}{
		{"identity_evidence", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.EvidenceKind = "other" }},
		{"endpoint", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.Endpoint = "http://127.0.0.1:8081" }},
		{"service_unit", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ServiceUnit = "other.service" }},
		{"boot_id", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.BootID = "other" }},
		{"pid", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.PID++ }},
		{"start_ticks", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ProcessStartTicks++ }},
		{"listener_ip", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ListenerIP = "127.0.0.2" }},
		{"listener_port", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ListenerPort++ }},
		{"listener_socket", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ListenerSocketInode++ }},
		{"executable_path", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ExecutablePath += ".other" }},
		{"executable_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ExecutableSHA256 = fmt.Sprintf("%064x", 90) }},
		{"executable_device", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ExecutableDevice++ }},
		{"executable_inode", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ExecutableInode++ }},
		{"executable_size", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ExecutableSize++ }},
		{"model_path", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ModelPath += ".other" }},
		{"model_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ModelSHA256 = fmt.Sprintf("%064x", 91) }},
		{"model_device", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ModelDevice++ }},
		{"model_inode", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ModelInode++ }},
		{"model_size", func(a *CheckpointVerifiedUnitAssociation) { a.Identity.ModelSize++ }},
		{"invocation", func(a *CheckpointVerifiedUnitAssociation) { a.Invocation = "abcdef0123456789abcdef0123456789" }},
		{"cgroup", func(a *CheckpointVerifiedUnitAssociation) { a.ControlGroup += ".other" }},
		{"receipt_evidence", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.EvidenceKind = "other" }},
		{"receipt_model_argument", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ModelArgument = "/tmp/model" }},
		{"receipt_argv_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArgvSHA256 = fmt.Sprintf("%064x", 92) }},
		{"receipt_binding_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.BindingSHA256 = fmt.Sprintf("%064x", 93) }},
		{"receipt_nonce", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.Nonce = fmt.Sprintf("%064x", 94) }},
		{"receipt_endpoint", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.Endpoint += "/other" }},
		{"receipt_unit", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ServiceUnit = "other.service" }},
		{"receipt_unit_association", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.UnitAssociation = "other" }},
		{"receipt_boot_id", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.BootID = "other" }},
		{"receipt_pid", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.PID++ }},
		{"receipt_start_ticks", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ProcessStartTicks++ }},
		{"receipt_socket", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ListenerSocketInode++ }},
		{"receipt_executable_path", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutablePath += ".other" }},
		{"receipt_executable_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutableSHA256 = fmt.Sprintf("%064x", 95) }},
		{"receipt_alias", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ActualAlias = "other" }},
		{"artifact_path", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArtifactPath += ".other" }},
		{"artifact_device", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArtifactDevice++ }},
		{"artifact_inode", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArtifactInode++ }},
		{"artifact_size", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArtifactSize++ }},
		{"artifact_hash", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ArtifactSHA256 = fmt.Sprintf("%064x", 96) }},
		{"artifact_verity", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.VerityDigest = "different" }},
		{"receipt_executable_device", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutableDevice++ }},
		{"receipt_executable_inode", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutableInode++ }},
		{"receipt_executable_size", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutableSize++ }},
		{"receipt_executable_verity", func(a *CheckpointVerifiedUnitAssociation) { a.Custody.ExecutableVerityDigest = "different" }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if sameManagedCheckpointAssociation(base, changed) {
				t.Fatal("immutable current-association substitution was accepted")
			}
		})
	}
	t.Run("timestamps_and_measured_footprint_excluded", func(t *testing.T) {
		changed := base
		changed.Identity.ObservedMappedBytes++
		changed.Identity.Fingerprint = "new measured mapping fingerprint"
		changed.Custody.PrelaunchBootNS++
		changed.Custody.StartBootNS++
		changed.Custody.StartedBootNS++
		if !sameManagedCheckpointAssociation(base, changed) {
			t.Fatal("time or changing measured footprint altered the stable current association")
		}
	})
}

func mustManagedArgv(t *testing.T, plan CheckpointLaunchPlan) []string {
	t.Helper()
	argv, err := managedCheckpointExpectedArgv(plan)
	if err != nil {
		t.Fatal(err)
	}
	return argv
}
