package nodeagent

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCheckpointFixedLauncherUsesFixedInvocation(t *testing.T) {
	cmd := fixedCheckpointCommand("/usr/libexec/vram-governor/checkpoint-fixed-launcher", []string{"-m", "/proc/self/fd/4"})
	if cmd.Path != "/usr/libexec/vram-governor/checkpoint-fixed-launcher" || !reflect.DeepEqual(cmd.Args, []string{cmd.Path, "-m", "/proc/self/fd/4"}) {
		t.Fatalf("fixed child command was not exact: %#v", cmd.Args)
	}
	if !reflect.DeepEqual(cmd.Env, []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent"}) {
		t.Fatalf("child received an uncontrolled environment: %#v", cmd.Env)
	}
}

func TestCheckpointFixedLauncherRejectsMissingContext(t *testing.T) {
	if err := RunCheckpointFixedLauncher(nil); err == nil {
		t.Fatal("nil startup context was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := RunCheckpointFixedLauncher(ctx); err == nil {
		t.Fatal("canceled startup context was accepted")
	}
}

func TestCheckpointFixedLauncherDoesNotAcceptCallerCommand(t *testing.T) {
	command := exec.Command("/bin/true")
	if len(command.Args) != 1 || command.Args[0] != "/bin/true" {
		t.Fatal("test fixture command malformed")
	}
	if checkpointFixedPlanPath != "/etc/vram-governor/llama-server-plan.json" || checkpointIdentityServiceUnit != "llama-server.service" {
		t.Fatal("fixed launcher path or unit became caller selectable")
	}
	plan := CheckpointLaunchPlan{Custody: CheckpointLaunchCustodyQuotas{Root: checkpointFixedCustodyRoot}, SnapshotRoot: checkpointFixedSnapshotRoot}
	if err := validateCheckpointFixedPlan(plan); err != nil {
		t.Fatalf("service-compatible fixed plan rejected: %v", err)
	}
	plan.Custody.Root = "/var/lib/other-custody"
	if err := validateCheckpointFixedPlan(plan); err == nil {
		t.Fatal("plan escaped the fixed service writable custody root")
	}
	plan.Custody.Root = checkpointFixedCustodyRoot
	plan.SnapshotRoot = "/tmp/snapshots"
	if err := validateCheckpointFixedPlan(plan); err == nil {
		t.Fatal("plan escaped the fixed service writable snapshot root")
	}
}

func TestCheckpointFixedLauncherStartupJoinRequiresTwoStableAssociations(t *testing.T) {
	plan := CheckpointLaunchPlan{Alias: "fixed-model", Model: CheckpointLaunchModel{SHA256: strings.Repeat("a", 64), Bytes: 4096}, Executable: CheckpointLaunchExecutable{Path: "/opt/llama-server", SHA256: strings.Repeat("b", 64)}, Endpoint: CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080}}
	stagedExecutablePath := "/var/lib/vram-governor/checkpoint-custody/executables/held-llama-server"
	unit := checkpointFixedUnitState{MainPID: 240, Invocation: strings.Repeat("c", 32), ControlGroup: "/system.slice/llama-server.service", Active: "activating", Sub: "start"}
	binding := CheckpointCustodyVerification{BindingSHA256: strings.Repeat("d", 64), Nonce: strings.Repeat("e", 64), Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified", BootID: "boot", PID: 240, ProcessStartTicks: 99, ListenerSocketInode: 31, ExecutablePath: stagedExecutablePath, ExecutableSHA256: plan.Executable.SHA256, ActualAlias: plan.Alias, ArtifactPath: "/var/lib/custody/models/model.gguf", ArtifactDevice: 4, ArtifactInode: 5, ArtifactSize: plan.Model.Bytes, ArtifactSHA256: plan.Model.SHA256}
	identity := CheckpointLocalIdentity{Endpoint: binding.Endpoint, ServiceUnit: binding.ServiceUnit, BootID: binding.BootID, PID: binding.PID, ProcessStartTicks: binding.ProcessStartTicks, ListenerSocketInode: binding.ListenerSocketInode, ExecutablePath: binding.ExecutablePath, ExecutableSHA256: binding.ExecutableSHA256, ModelPath: binding.ArtifactPath, ModelDevice: binding.ArtifactDevice, ModelInode: binding.ArtifactInode, ModelSize: binding.ArtifactSize, ModelSHA256: binding.ArtifactSHA256, Fingerprint: "fresh"}
	runtimeVersion := "0.3.0-dev (build 1, commit 62acc89), GNU 13.3.0 Linux x86_64"
	placement := CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", ChildMaskUUID: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: runtimeVersion, ObservedAt: "2026-10-01T00:00:00Z"}
	plan.Version = checkpointLaunchPlanVersion2
	plan.Placement = &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: placement.PhysicalIdentity, RuntimeDeviceToken: "CUDA0", RuntimeVersion: runtimeVersion, MaxAccelerators: 1, OffloadPolicy: "full_gpu", MinGPUBytes: 1 << 20, MaxHostRSSBytes: 8 << 30}
	footprint := checkpointOffloadEvidence{GPUBytes: 2 << 20, HostRSS: 1 << 30, LayersGPU: 33, LayersTotal: 33}
	sample := checkpointFixedStartupSample{unit: unit, binding: binding, identity: identity, placement: placement, footprint: footprint, childParent: 120, supervisorStartTicks: 42, childCgroup: unit.ControlGroup, supervisorCgroup: unit.ControlGroup}
	if err := validateCheckpointFixedStartupPair(sample, sample, plan, stagedExecutablePath, 240, 120); err != nil {
		t.Fatalf("positive controlled startup join rejected: %v", err)
	}
	fluctuating := sample
	fluctuating.footprint.GPUBytes += 512 << 10
	fluctuating.footprint.HostRSS += 64 << 20
	if err := validateCheckpointFixedStartupPair(sample, fluctuating, plan, stagedExecutablePath, 240, 120); err != nil {
		t.Fatalf("valid fluctuating footprint rejected: %v", err)
	}
	for name, mutate := range map[string]func(*checkpointFixedStartupSample){
		"first sample gpu below bound":   func(s *checkpointFixedStartupSample) { s.footprint.GPUBytes = 1 },
		"second sample host above bound": func(s *checkpointFixedStartupSample) { s.footprint.HostRSS = plan.Placement.MaxHostRSSBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			first, second := sample, sample
			if strings.HasPrefix(name, "first") {
				mutate(&first)
			} else {
				mutate(&second)
			}
			if err := validateCheckpointFixedStartupPair(first, second, plan, stagedExecutablePath, 240, 120); err == nil {
				t.Fatal("out-of-bounds individual footprint sample was accepted")
			}
		})
	}
	mutations := map[string]func(*checkpointFixedStartupSample){
		"supervisor main pid":            func(s *checkpointFixedStartupSample) { s.unit.MainPID = 120 },
		"non activating":                 func(s *checkpointFixedStartupSample) { s.unit.Active = "active"; s.unit.Sub = "running" },
		"wrong invocation":               func(s *checkpointFixedStartupSample) { s.unit.Invocation = string(make([]byte, 32)) },
		"wrong cgroup":                   func(s *checkpointFixedStartupSample) { s.supervisorCgroup = "/system.slice/other.service" },
		"wrong parent":                   func(s *checkpointFixedStartupSample) { s.childParent = 121 },
		"missing supervisor incarnation": func(s *checkpointFixedStartupSample) { s.supervisorStartTicks = 0 },
		"wrong alias":                    func(s *checkpointFixedStartupSample) { s.binding.ActualAlias = "other" },
		"wrong receipt model":            func(s *checkpointFixedStartupSample) { s.binding.ArtifactSHA256 = strings.Repeat("f", 64) },
		"wrong process incarnation":      func(s *checkpointFixedStartupSample) { s.identity.ProcessStartTicks++ },
		"wrong sole listener":            func(s *checkpointFixedStartupSample) { s.identity.ListenerSocketInode++ },
		"forged staged executable": func(s *checkpointFixedStartupSample) {
			s.binding.ExecutablePath = plan.Executable.Path
			s.identity.ExecutablePath = plan.Executable.Path
		},
		"wrong physical GPU": func(s *checkpointFixedStartupSample) {
			s.placement.PhysicalIdentity = "GPU-11111111-2222-3333-4444-555555555555"
		},
		"missing full layer evidence": func(s *checkpointFixedStartupSample) { s.footprint.LayersGPU-- },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			bad := sample
			mutate(&bad)
			if err := validateCheckpointFixedStartupPair(bad, bad, plan, stagedExecutablePath, 240, 120); err == nil {
				t.Fatal("faulted startup association was accepted")
			}
		})
	}
	changed := sample
	changed.unit.Invocation = strings.Repeat("f", 32)
	if err := validateCheckpointFixedStartupPair(sample, changed, plan, stagedExecutablePath, 240, 120); err == nil {
		t.Fatal("fresh startup drift was accepted")
	}
	order := []string{}
	steps := checkpointFixedStartupSteps{
		commit: func(context.Context) error { order = append(order, "commit"); return nil },
		mainPID: func(_ context.Context, pid int) error {
			if pid != 240 {
				t.Fatalf("unexpected worker PID %d", pid)
			}
			order = append(order, "mainpid")
			return nil
		},
		barrier: func(context.Context) error { order = append(order, "barrier"); return nil },
		join:    func(context.Context) error { order = append(order, "join"); return nil },
		ready:   func(context.Context) error { order = append(order, "ready"); return nil },
	}
	if err := runCheckpointFixedStartupSteps(context.Background(), 240, steps); err != nil {
		t.Fatalf("ordered positive protocol rejected: %v", err)
	}
	if !reflect.DeepEqual(order, []string{"commit", "mainpid", "barrier", "join", "ready"}) {
		t.Fatalf("startup messages escaped the required order: %v", order)
	}
	phaseOrder := []string{}
	if err := runCheckpointFixedCommitAfterReadiness(context.Background(), func(context.Context) error {
		phaseOrder = append(phaseOrder, "health-ready")
		return nil
	}, func(context.Context) error {
		phaseOrder = append(phaseOrder, "custody-commit")
		return nil
	}); err != nil || !reflect.DeepEqual(phaseOrder, []string{"health-ready", "custody-commit"}) {
		t.Fatalf("custody commit preceded loading readiness: order=%v err=%v", phaseOrder, err)
	}
	phaseOrder = nil
	if err := runCheckpointFixedCommitAfterReadiness(context.Background(), func(context.Context) error {
		phaseOrder = append(phaseOrder, "health-timeout")
		return context.DeadlineExceeded
	}, func(context.Context) error {
		phaseOrder = append(phaseOrder, "custody-commit")
		return nil
	}); !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(phaseOrder, []string{"health-timeout"}) {
		t.Fatalf("failed health wait allowed custody commit: order=%v err=%v", phaseOrder, err)
	}
	for failAt, name := range []string{"commit", "mainpid", "barrier", "join", "ready"} {
		seen := []string{}
		failing := checkpointFixedStartupSteps{}
		failure := errors.New("injected " + name + " failure")
		makeStep := func(step string) func() error {
			return func() error {
				seen = append(seen, step)
				if step == name {
					return failure
				}
				return nil
			}
		}
		_ = makeStep
		failing.commit = func(context.Context) error { return makeStep("commit")() }
		failing.mainPID = func(context.Context, int) error { return makeStep("mainpid")() }
		failing.barrier = func(context.Context) error { return makeStep("barrier")() }
		failing.join = func(context.Context) error { return makeStep("join")() }
		failing.ready = func(context.Context) error { return makeStep("ready")() }
		if err := runCheckpointFixedStartupSteps(context.Background(), 240, failing); !errors.Is(err, failure) {
			t.Fatalf("step %s failure was not returned: %v", name, err)
		}
		if len(seen) != failAt+1 {
			t.Fatalf("protocol continued after %s failed: %v", name, seen)
		}
	}
	cleanupCalls, releaseCalls := 0, 0
	if err := cleanupCheckpointFixedOwnedChild(context.Background(), func(context.Context) (bool, error) { cleanupCalls++; return false, errors.New("reap uncertain") }, func(context.Context) error { releaseCalls++; return nil }); err == nil || cleanupCalls != 1 || releaseCalls != 0 {
		t.Fatalf("unknown reap released charged ownership: err=%v cancel/reap=%d release=%d", err, cleanupCalls, releaseCalls)
	}
	states, signals, releases := 0, 0, 0
	retentionCtx, cancelRetention := context.WithTimeout(context.Background(), time.Second)
	defer cancelRetention()
	err := retainCheckpointFixedOwnership(retentionCtx, checkpointFixedRetentionSeam{
		state: func() (bool, int) { states++; return states >= 2, 17 },
		signal: func(pidfd int) error {
			if pidfd != 17 {
				t.Fatalf("retention signaled non-owned authority %d", pidfd)
			}
			signals++
			return nil
		},
		release: func(context.Context) error {
			releases++
			if releases == 1 {
				return errors.New("temporary cleanup failure")
			}
			return nil
		},
		interval: time.Millisecond,
	})
	if err != nil || signals == 0 || releases != 2 {
		t.Fatalf("retention failed to wait, signal exact pidfd, and retry terminal cleanup: err=%v signals=%d releases=%d", err, signals, releases)
	}
}

func TestCheckpointFixedLauncherRuntimeOptionsCommand(t *testing.T) {
	plan := checkpointPlacementFixture()
	placement := CheckpointDevicePlacement{
		Backend: plan.Placement.Backend, PhysicalIdentity: plan.Placement.PhysicalIdentity,
		ChildMaskUUID: plan.Placement.PhysicalIdentity, RuntimeDeviceToken: plan.Placement.RuntimeDeviceToken,
		RuntimeVersion: plan.Placement.RuntimeVersion, ObservedAt: "source-test-only",
	}
	legacyCommand, _, err := fixedCheckpointPlacementCommand("/server", plan, placement)
	if err != nil {
		t.Fatalf("v2 absence command rejected: %v", err)
	}
	legacyArgs := []string{"-m", "{CHECKPOINT_MODEL}", "--alias", "managed-model", "--host", "127.0.0.1", "--port", "8080", "--no-webui", "-c", "4096", "--parallel", "4", "--slot-save-path", "/snapshots", "--device", "CUDA0", "--split-mode", "none", "--main-gpu", "0", "--n-gpu-layers", "all"}
	if !reflect.DeepEqual(legacyCommand.Args, append([]string{legacyCommand.Path}, legacyArgs...)) {
		t.Fatalf("v2 absence changed its pre-feature fixed argv: args=%#v", legacyCommand.Args)
	}
	legacyEnv := []string{"LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "HOME=/nonexistent", "CUDA_DEVICE_ORDER=PCI_BUS_ID", "CUDA_VISIBLE_DEVICES=" + placement.PhysicalIdentity}
	if !reflect.DeepEqual(legacyCommand.Env, legacyEnv) {
		t.Fatalf("v2 absence changed its fixed environment: %#v", legacyCommand.Env)
	}

	plan.RuntimeOptions = &CheckpointLaunchRuntimeOptions{KVUnified: true, FlashAttention: "off", CheckpointDescriptor: true}
	command, _, err := fixedCheckpointPlacementCommand("/server", plan, placement)
	if err != nil {
		t.Fatalf("supported opt-in command rejected: %v", err)
	}
	wantArgs := append(append([]string{command.Path}, legacyArgs...), "--kv-unified", "--flash-attn", "off")
	if !reflect.DeepEqual(command.Args, wantArgs) {
		t.Fatalf("opt-in argv does not append exactly the reviewed tuple: %#v", command.Args)
	}
	wantEnv := append(append([]string(nil), legacyEnv...), "LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=1")
	if !reflect.DeepEqual(command.Env, wantEnv) {
		t.Fatalf("opt-in environment does not append the fixed descriptor flag: %#v", command.Env)
	}

	for _, bad := range []*CheckpointLaunchRuntimeOptions{
		{KVUnified: false, FlashAttention: "off", CheckpointDescriptor: true},
		{KVUnified: true, FlashAttention: "auto", CheckpointDescriptor: true},
		{KVUnified: true, FlashAttention: "off", CheckpointDescriptor: false},
	} {
		invalid := plan
		invalid.RuntimeOptions = bad
		if cmd, _, err := fixedCheckpointPlacementCommand("/server", invalid, placement); err == nil || cmd != nil {
			t.Fatalf("invalid directly constructed runtime options reached command creation: options=%+v cmd=%#v", bad, cmd)
		}
	}
	legacy := plan
	legacy.Version = checkpointLaunchPlanVersion
	if cmd, _, err := fixedCheckpointPlacementCommand("/server", legacy, placement); err == nil || cmd != nil {
		t.Fatalf("v1 directly constructed runtime options reached command creation: cmd=%#v", cmd)
	}
}

func TestCheckpointLaunchPlanRuntimeOptionsSpecCopy(t *testing.T) {
	plan := checkpointPlacementFixture()
	plan.RuntimeOptions = &CheckpointLaunchRuntimeOptions{KVUnified: true, FlashAttention: "off", CheckpointDescriptor: true}
	pinned := &PinnedCheckpointLaunchPlan{plan: plan}
	spec := pinned.Spec()
	if spec.RuntimeOptions == nil || spec.RuntimeOptions == plan.RuntimeOptions {
		t.Fatal("Spec did not return an independent runtime_options pointer")
	}
	spec.RuntimeOptions.FlashAttention = "mutated"
	spec.RuntimeOptions.KVUnified = false
	if plan.RuntimeOptions.FlashAttention != "off" || !plan.RuntimeOptions.KVUnified {
		t.Fatalf("mutating Spec changed the pinned runtime options: %+v", plan.RuntimeOptions)
	}
}
