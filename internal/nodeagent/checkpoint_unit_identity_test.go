package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckpointUnitIdentityParsesStrictSystemdProperties(t *testing.T) {
	raw := []byte("MainPID=42\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=/system.slice/llama-server.service\nActiveState=active\nSubState=running\n")
	state, err := parseCheckpointUnitProperties(raw)
	if err != nil || state.MainPID != 42 || state.InvocationID != "0123456789abcdef0123456789abcdef" || state.ActiveState != "active" || state.SubState != "running" {
		t.Fatalf("valid fixed-unit properties rejected: state=%+v err=%v", state, err)
	}
	for name, bad := range map[string][]byte{
		"missing":         []byte("MainPID=42\n"),
		"duplicate":       []byte(strings.Replace(string(raw), "SubState=running\n", "SubState=running\nSubState=running\n", 1)),
		"unexpected":      []byte(string(raw) + "Environment=PATH=x\n"),
		"malformed":       []byte(strings.Replace(string(raw), "MainPID=42", "MainPID=42=43", 1)),
		"zero pid":        []byte(strings.Replace(string(raw), "MainPID=42", "MainPID=0", 1)),
		"bad invocation":  []byte(strings.Replace(string(raw), "0123456789abcdef0123456789abcdef", "invalid", 1)),
		"zero invocation": []byte(strings.Replace(string(raw), "0123456789abcdef0123456789abcdef", strings.Repeat("0", 32), 1)),
		"bad cgroup":      []byte(strings.Replace(string(raw), "/system.slice/llama-server.service", "/system.slice/../llama-server.service", 1)),
		"oversized":       []byte(strings.Repeat("x", checkpointUnitMaxOutput+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCheckpointUnitProperties(bad); err == nil {
				t.Fatalf("accepted malformed systemd property fixture %q", name)
			}
		})
	}
}

func TestCheckpointUnitIdentityRequiresExactUnifiedCgroupMembership(t *testing.T) {
	const expected = "/system.slice/llama-server.service"
	if got, err := parseCheckpointCgroupMembership([]byte("0::"+expected+"\n"), expected); err != nil || got != expected {
		t.Fatalf("exact unified cgroup membership rejected: %q %v", got, err)
	}
	for name, raw := range map[string][]byte{
		"prefix":            []byte("0::/system.slice/llama-server.service-extra\n"),
		"v1 only":           []byte("2:cpu:/system.slice/llama-server.service\n"),
		"ambiguous unified": []byte("0::" + expected + "\n0::" + expected + "\n"),
		"malformed":         []byte("0::/system.slice/../llama-server.service\n"),
		"oversized":         []byte("0::" + expected + "\n" + strings.Repeat("x", checkpointUnitMaxCgroupBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCheckpointCgroupMembership(raw, expected); err == nil {
				t.Fatalf("accepted invalid cgroup membership fixture %q", name)
			}
		})
	}
}

func TestCheckpointUnitIdentityJoinsCustodyLocalIdentityAndStableUnit(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	association, err := joinCheckpointUnitIdentity(binding, identity, "model-alias", first, second)
	if err != nil || association.Custody.Nonce != binding.Nonce || association.Identity.Fingerprint != identity.Fingerprint || association.Invocation != first.InvocationID || association.ControlGroup != first.ControlGroup {
		t.Fatalf("valid local managed-unit association rejected: association=%+v err=%v", association, err)
	}
	if association.Custody.UnitAssociation != "label-only-unverified" {
		t.Fatalf("association rewrote custody's label-only receipt: %q", association.Custody.UnitAssociation)
	}
}

func TestCheckpointUnitIdentityRejectsCustodyAliasAndProcessDrift(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	mutations := map[string]func(*CheckpointCustodyVerification, *CheckpointLocalIdentity, *checkpointUnitObservation, *checkpointUnitObservation){
		"missing binding digest": func(b *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			b.BindingSHA256 = ""
		},
		"receipt label": func(b *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			b.UnitAssociation = "verified"
		},
		"wrong custody unit": func(b *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			b.ServiceUnit = "proxy.service"
		},
		"wrong expected alias": func(b *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			b.ActualAlias = "other"
		},
		"boot drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.BootID = "other"
		},
		"pid drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.PID++
		},
		"start drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.ProcessStartTicks++
		},
		"socket drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.ListenerSocketInode++
		},
		"executable drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.ExecutablePath = "/usr/bin/wrapper"
		},
		"source drift": func(_ *CheckpointCustodyVerification, i *CheckpointLocalIdentity, _, _ *checkpointUnitObservation) {
			i.ModelInode++
		},
		"unit pid drift": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.MainPID++
		},
		"invocation drift": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.InvocationID = "fedcba9876543210fedcba9876543210"
		},
		"cgroup drift": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.ControlGroup = "/system.slice/other.service"
		},
		"inactive": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.ActiveState = "inactive"
		},
		"not running": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.SubState = "start"
		},
		"nonmember": func(_ *CheckpointCustodyVerification, _ *CheckpointLocalIdentity, _ *checkpointUnitObservation, b *checkpointUnitObservation) {
			b.CgroupMembers += "-worker"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			b, i, a, z := binding, identity, first, second
			mutate(&b, &i, &a, &z)
			if _, err := joinCheckpointUnitIdentity(b, i, "model-alias", a, z); err == nil {
				t.Fatalf("accepted %q drift", name)
			}
		})
	}
}

func TestCheckpointUnitIdentityRejectsChangingFreshSamples(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	for name, mutate := range map[string]func(*checkpointUnitObservation){
		"main pid":          func(o *checkpointUnitObservation) { o.MainPID++ },
		"invocation":        func(o *checkpointUnitObservation) { o.InvocationID = "fedcba9876543210fedcba9876543210" },
		"control group":     func(o *checkpointUnitObservation) { o.ControlGroup = "/system.slice/other.service" },
		"active state":      func(o *checkpointUnitObservation) { o.ActiveState = "reloading" },
		"sub state":         func(o *checkpointUnitObservation) { o.SubState = "dead" },
		"cgroup membership": func(o *checkpointUnitObservation) { o.CgroupMembers = "/system.slice/other.service" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := second
			mutate(&changed)
			if _, err := joinCheckpointUnitIdentity(binding, identity, "model-alias", first, changed); err == nil {
				t.Fatalf("accepted changing second unit sample: %q", name)
			}
		})
	}
}

func TestCheckpointUnitIdentityRejectsInactiveStableUnit(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	for name, state := range map[string]string{"inactive": "inactive", "starting": "activating", "stopped": "dead"} {
		t.Run(name, func(t *testing.T) {
			a, b := first, second
			a.ActiveState, b.ActiveState = state, state
			if _, err := joinCheckpointUnitIdentity(binding, identity, "model-alias", a, b); err == nil {
				t.Fatalf("accepted stable unit state %q", state)
			}
		})
	}
	for name, state := range map[string]string{"starting": "start", "exited": "exited"} {
		t.Run(name, func(t *testing.T) {
			a, b := first, second
			a.SubState, b.SubState = state, state
			if _, err := joinCheckpointUnitIdentity(binding, identity, "model-alias", a, b); err == nil {
				t.Fatalf("accepted stable substate %q", state)
			}
		})
	}
}

func TestCheckpointUnitIdentityRejectsIncompleteLocalPolicy(t *testing.T) {
	base := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	for name, mutate := range map[string]func(*CheckpointUnitIdentityRequest){
		"missing custody": func(r *CheckpointUnitIdentityRequest) { r.Custody = nil },
		"wrong unit":      func(r *CheckpointUnitIdentityRequest) { r.Identity.ServiceUnit = "proxy.service" },
		"missing alias":   func(r *CheckpointUnitIdentityRequest) { r.ExpectedAlias = "" },
		"trimmed alias":   func(r *CheckpointUnitIdentityRequest) { r.ExpectedAlias = " model-alias " },
	} {
		t.Run(name, func(t *testing.T) {
			req := base
			mutate(&req)
			if _, err := ObserveCheckpointManagedUnit(context.Background(), req); err == nil {
				t.Fatal("accepted incomplete local checkpoint unit policy")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveCheckpointManagedUnit(ctx, base); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observation was not rejected: %v", err)
	}
}

func TestCheckpointUnitIdentityValidatesPinnedIdentityRequest(t *testing.T) {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator) + "models"
	base := CheckpointIdentityRequest{
		Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit,
		ModelPath: filepath.Join(root, "demo.gguf"), ExpectedModelSHA256: stringsOf('a', 64),
		ApprovedModelRoots: []string{root}, ExpectedExecutableSHA256: stringsOf('b', 64),
	}
	if err := validateCheckpointUnitIdentityRequest(base); err != nil {
		t.Fatalf("valid pinned identity request rejected: %v", err)
	}
	for name, mutate := range map[string]func(*CheckpointIdentityRequest){
		"model digest":        func(r *CheckpointIdentityRequest) { r.ExpectedModelSHA256 = "bad" },
		"executable digest":   func(r *CheckpointIdentityRequest) { r.ExpectedExecutableSHA256 = "bad" },
		"too many roots":      func(r *CheckpointIdentityRequest) { r.ApprovedModelRoots = make([]string, 17) },
		"relative model path": func(r *CheckpointIdentityRequest) { r.ModelPath = "model.gguf" },
		"model traversal": func(r *CheckpointIdentityRequest) {
			r.ModelPath = root + string(filepath.Separator) + ".." + string(filepath.Separator) + "secret.gguf"
		},
		"root traversal": func(r *CheckpointIdentityRequest) {
			r.ApprovedModelRoots = []string{root + string(filepath.Separator) + ".." + string(filepath.Separator) + "outside"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := base
			mutate(&req)
			if err := validateCheckpointUnitIdentityRequest(req); err == nil {
				t.Fatalf("accepted invalid identity request %q", name)
			}
		})
	}
}

func checkpointUnitJoinFixture() (CheckpointCustodyVerification, CheckpointLocalIdentity, checkpointUnitObservation, checkpointUnitObservation) {
	binding := CheckpointCustodyVerification{
		BindingSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), Endpoint: "http://127.0.0.1:8080",
		ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified", BootID: "00000000-0000-0000-0000-000000000001",
		PID: 4242, ProcessStartTicks: 123456, ListenerSocketInode: 987654, ExecutablePath: "/usr/bin/llama-server",
		ExecutableSHA256: strings.Repeat("c", 64), ActualAlias: "model-alias", ArtifactPath: "/private/models/model.gguf",
		ArtifactDevice: 11, ArtifactInode: 22, ArtifactSize: 4096, ArtifactSHA256: strings.Repeat("d", 64),
	}
	identity := CheckpointLocalIdentity{
		Endpoint: binding.Endpoint, ServiceUnit: binding.ServiceUnit, BootID: binding.BootID, PID: binding.PID,
		ProcessStartTicks: binding.ProcessStartTicks, ListenerSocketInode: binding.ListenerSocketInode,
		ExecutablePath: binding.ExecutablePath, ExecutableSHA256: binding.ExecutableSHA256,
		ModelPath: binding.ArtifactPath, ModelDevice: binding.ArtifactDevice, ModelInode: binding.ArtifactInode,
		ModelSize: binding.ArtifactSize, ModelSHA256: binding.ArtifactSHA256, Fingerprint: strings.Repeat("e", 64),
	}
	observation := checkpointUnitObservation{
		MainPID: binding.PID, InvocationID: "0123456789abcdef0123456789abcdef", ControlGroup: "/system.slice/llama-server.service",
		ActiveState: "active", SubState: "running", CgroupMembers: "/system.slice/llama-server.service",
	}
	return binding, identity, observation, observation
}
