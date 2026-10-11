//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCheckpointUnitIdentityLinuxSyntheticCollectorJoinsTwoFreshSamples(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	collectCalls, verifyCalls, identityCalls := 0, 0, 0
	source := checkpointUnitLinuxSource{
		procRoot: "/synthetic/proc",
		collect: func(ctx context.Context, expectedPID int) (checkpointUnitObservation, error) {
			collectCalls++
			if err := ctx.Err(); err != nil {
				return checkpointUnitObservation{}, err
			}
			if expectedPID != 0 && expectedPID != identity.PID {
				t.Fatalf("sample was not bound to the expected MainPID: %d", expectedPID)
			}
			if collectCalls < 4 {
				return first, nil
			}
			if collectCalls == 4 {
				return second, nil
			}
			t.Fatalf("unexpected extra sample: %d", collectCalls)
			return checkpointUnitObservation{}, errors.New("unreachable")
		},
		verifyCustody: func(_ context.Context, _ *CheckpointCustodyStore, endpoint, unit string) (CheckpointCustodyVerification, bool, error) {
			verifyCalls++
			if endpoint != identity.Endpoint || unit != checkpointIdentityServiceUnit {
				t.Fatalf("custody was not verified for fixed local identity: %q %q", endpoint, unit)
			}
			return binding, true, nil
		},
		observeLocal: func(_ context.Context, req CheckpointIdentityRequest, endpoint string, host net.IP, port uint16, local checkpointLinuxSource) (CheckpointLocalIdentity, error) {
			identityCalls++
			if req.ServiceUnit != checkpointIdentityServiceUnit || endpoint != identity.Endpoint || host.String() != "127.0.0.1" || port != 8080 {
				t.Fatal("local identity observer received unexpected request")
			}
			if pid, err := local.mainPID(context.Background(), checkpointIdentityServiceUnit); err != nil || pid != identity.PID {
				t.Fatalf("identity observer did not use the bounded fixed-unit sample: pid=%d err=%v", pid, err)
			}
			if _, err := local.mainPID(context.Background(), checkpointIdentityServiceUnit); err != nil {
				t.Fatalf("identity observer second MainPID check failed: %v", err)
			}
			return identity, nil
		},
	}
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	association, err := observeCheckpointManagedUnitLinux(context.Background(), req, source)
	if err != nil || association.Custody.Nonce != binding.Nonce {
		t.Fatalf("synthetic local association failed: %+v err=%v", association, err)
	}
	if collectCalls != 4 || verifyCalls != 2 || identityCalls != 1 {
		t.Fatalf("unexpected observation counts: collect=%d custody=%d identity=%d", collectCalls, verifyCalls, identityCalls)
	}
}

func TestCheckpointControlledSourceUnitJoinKeepsSourceIdentityStable(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	binding.EvidenceKind = "controlled-source-fs-verity-v2"
	binding.ModelArgument = "/proc/self/fd/4"
	binding.ArgvSHA256 = strings.Repeat("a", 64)
	binding.ExecutableDevice = 1
	binding.ExecutableInode = 2
	binding.ExecutableSize = 3
	binding.ExecutableVerityDigest = strings.Repeat("b", 64)
	identity.EvidenceKind = binding.EvidenceKind
	identity.ObservedMappedBytes = 0
	identity.Fingerprint = checkpointIdentityFingerprint(identity)
	first.MainPID, second.MainPID = identity.PID, identity.PID
	joined, err := joinCheckpointUnitIdentity(binding, identity, binding.ActualAlias, first, second)
	if err != nil || joined.Identity.Fingerprint != identity.Fingerprint {
		t.Fatalf("authenticated controlled-source unit join failed: %+v err=%v", joined, err)
	}
	mapped := identity
	mapped.ObservedMappedBytes = identity.ModelSize / 2
	if checkpointIdentityFingerprint(mapped) != identity.Fingerprint {
		t.Fatal("controlled source fingerprint changed when runtime mapping coverage changed")
	}
	legacy := binding
	legacy.EvidenceKind = ""
	legacy.ModelArgument = ""
	legacy.ArgvSHA256 = ""
	if _, err := joinCheckpointUnitIdentity(legacy, identity, binding.ActualAlias, first, second); err == nil {
		t.Fatal("caller-created controlled identity promoted an unauthenticated legacy receipt")
	}
}

func TestCheckpointUnitIdentityLinuxRejectsNilAndCanceledContextBeforeCollection(t *testing.T) {
	_, identity, first, _ := checkpointUnitJoinFixture()
	collectCalls, verifyCalls, identityCalls := 0, 0, 0
	source := checkpointUnitLinuxSource{
		procRoot: "/synthetic/proc",
		collect:  func(context.Context, int) (checkpointUnitObservation, error) { collectCalls++; return first, nil },
		verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
			verifyCalls++
			return CheckpointCustodyVerification{}, false, nil
		},
		observeLocal: func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error) {
			identityCalls++
			return identity, nil
		},
	}
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	if _, err := observeCheckpointManagedUnitLinux(nil, req, source); err == nil {
		t.Fatal("accepted a nil context")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observeCheckpointManagedUnitLinux(canceled, req, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context was not returned: %v", err)
	}
	if collectCalls != 0 || verifyCalls != 0 || identityCalls != 0 {
		t.Fatalf("downstream observers ran before context validation: collect=%d custody=%d identity=%d", collectCalls, verifyCalls, identityCalls)
	}
}

func TestCheckpointUnitIdentityLinuxReverifiesCustodyAfterFinalSample(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	for name, final := range map[string]struct {
		binding CheckpointCustodyVerification
		ok      bool
		err     error
	}{
		"nonce drift": {binding: func() CheckpointCustodyVerification {
			changed := binding
			changed.Nonce = strings.Repeat("f", 64)
			return changed
		}(), ok: true},
		"binding disappeared": {binding: binding, ok: false},
		"verification error":  {binding: binding, ok: false, err: errors.New("synthetic custody error")},
	} {
		t.Run(name, func(t *testing.T) {
			collectCalls, verifyCalls, identityCalls := 0, 0, 0
			source := checkpointUnitLinuxSource{
				procRoot: "/synthetic/proc",
				collect: func(context.Context, int) (checkpointUnitObservation, error) {
					collectCalls++
					if collectCalls == 2 {
						return second, nil
					}
					return first, nil
				},
				verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
					verifyCalls++
					if verifyCalls == 1 {
						return binding, true, nil
					}
					return final.binding, final.ok, final.err
				},
				observeLocal: func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error) {
					identityCalls++
					return identity, nil
				},
			}
			req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
			if _, err := observeCheckpointManagedUnitLinux(context.Background(), req, source); err == nil {
				t.Fatal("accepted final custody drift or loss")
			}
			if collectCalls != 2 || verifyCalls != 2 || identityCalls != 1 {
				t.Fatalf("final custody check did not follow final sample: collect=%d custody=%d identity=%d", collectCalls, verifyCalls, identityCalls)
			}
		})
	}
}

func TestCheckpointUnitIdentityLinuxExpiredCollectorDeadlineSkipsDownstream(t *testing.T) {
	_, identity, _, _ := checkpointUnitJoinFixture()
	collectCalls, verifyCalls, identityCalls := 0, 0, 0
	source := checkpointUnitLinuxSource{
		procRoot: "/synthetic/proc",
		collect: func(ctx context.Context, _ int) (checkpointUnitObservation, error) {
			collectCalls++
			<-ctx.Done()
			return checkpointUnitObservation{}, ctx.Err()
		},
		verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
			verifyCalls++
			return CheckpointCustodyVerification{}, false, nil
		},
		observeLocal: func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error) {
			identityCalls++
			return CheckpointLocalIdentity{}, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	started := time.Now()
	if _, err := observeCheckpointManagedUnitLinux(ctx, req, source); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired collector context did not fail with deadline: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("expired collector deadline returned too slowly: %v", elapsed)
	}
	if collectCalls != 1 || verifyCalls != 0 || identityCalls != 0 {
		t.Fatalf("deadline did not fence downstream observers: collect=%d custody=%d identity=%d", collectCalls, verifyCalls, identityCalls)
	}
}

func TestCheckpointUnitIdentityLinuxSyntheticCollectorRejectsUnitDrift(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	for name, mutate := range map[string]func(*checkpointUnitObservation){
		"invocation":    func(o *checkpointUnitObservation) { o.InvocationID = "fedcba9876543210fedcba9876543210" },
		"control group": func(o *checkpointUnitObservation) { o.ControlGroup = "/system.slice/other.service" },
		"main pid":      func(o *checkpointUnitObservation) { o.MainPID++ },
		"inactive":      func(o *checkpointUnitObservation) { o.ActiveState = "inactive" },
		"starting":      func(o *checkpointUnitObservation) { o.SubState = "start" },
		"cgroup prefix": func(o *checkpointUnitObservation) { o.CgroupMembers += "-child" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := second
			mutate(&changed)
			calls := 0
			source := checkpointUnitLinuxSource{
				procRoot: "/synthetic/proc",
				collect: func(context.Context, int) (checkpointUnitObservation, error) {
					calls++
					if calls == 1 {
						return first, nil
					}
					return changed, nil
				},
				verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
					return binding, true, nil
				},
				observeLocal: func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error) {
					return identity, nil
				},
			}
			req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
			if _, err := observeCheckpointManagedUnitLinux(context.Background(), req, source); err == nil {
				t.Fatalf("accepted synthetic unit drift %q", name)
			}
		})
	}
}

func TestCheckpointUnitIdentityLinuxCgroupReaderIsNonblockingAndBounded(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "cgroup")
	if err := unixMkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readCheckpointCgroupMembership(context.Background(), fifo, "/system.slice/llama-server.service")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a FIFO as proc cgroup membership")
		}
	case <-timeAfterUnitBound():
		t.Fatal("cgroup reader blocked on a FIFO")
	}
	regular := filepath.Join(dir, "oversized")
	if err := os.WriteFile(regular, []byte("0::/system.slice/llama-server.service\n"+strings.Repeat("x", checkpointUnitMaxCgroupBytes)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpointCgroupMembership(context.Background(), regular, "/system.slice/llama-server.service"); err == nil {
		t.Fatal("accepted oversized cgroup membership")
	}
}

func TestCheckpointUnitIdentityLinuxHonorsCancellationAndCustodyFailure(t *testing.T) {
	_, identity, first, _ := checkpointUnitJoinFixture()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	collectCalled := false
	source := checkpointUnitLinuxSource{procRoot: "/synthetic/proc", collect: func(ctx context.Context, _ int) (checkpointUnitObservation, error) {
		collectCalled = true
		return first, ctx.Err()
	}}
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	if _, err := observeCheckpointManagedUnitLinux(canceled, req, source); !errors.Is(err, context.Canceled) || collectCalled {
		t.Fatalf("cancellation was not honored before collection: called=%v err=%v", collectCalled, err)
	}
	collectCalls := 0
	source.collect = func(context.Context, int) (checkpointUnitObservation, error) { collectCalls++; return first, nil }
	source.verifyCustody = func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
		return CheckpointCustodyVerification{}, false, nil
	}
	if _, err := observeCheckpointManagedUnitLinux(context.Background(), req, source); err == nil || collectCalls != 1 {
		t.Fatalf("missing authenticated custody binding was accepted: calls=%d err=%v", collectCalls, err)
	}
}

func TestCheckpointUnitIdentityLinuxProcCgroupReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	link := filepath.Join(dir, "cgroup")
	if err := os.WriteFile(actual, []byte("0::/system.slice/llama-server.service\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readCheckpointCgroupMembership(context.Background(), link, "/system.slice/llama-server.service"); err == nil {
		t.Fatal("followed a symlink for process cgroup membership")
	}
}

func TestCheckpointUnitIdentityLinuxSystemdOutputWriterEnforcesByteCap(t *testing.T) {
	output := &checkpointUnitOutput{max: 8}
	if n, err := output.Write([]byte("12345678")); err != nil || n != 8 {
		t.Fatalf("bounded systemd writer rejected in-range output: n=%d err=%v", n, err)
	}
	if n, err := output.Write([]byte("9")); err == nil || n != 0 {
		t.Fatalf("bounded systemd writer accepted excess output: n=%d err=%v", n, err)
	}
	if got := string(output.Bytes()); got != "12345678" {
		t.Fatalf("excess systemd output changed retained buffer: %q", got)
	}
}

func TestCheckpointUnitIdentityLinuxChecksContextAfterFinalCustodyVerification(t *testing.T) {
	binding, identity, first, second := checkpointUnitJoinFixture()
	canceled, cancel := context.WithCancel(context.Background())
	collectCalls, verifyCalls := 0, 0
	source := checkpointUnitLinuxSource{
		procRoot: "/synthetic/proc",
		collect: func(context.Context, int) (checkpointUnitObservation, error) {
			collectCalls++
			if collectCalls == 2 {
				cancel()
				return second, nil
			}
			return first, nil
		},
		verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
			verifyCalls++
			return binding, true, nil
		},
		observeLocal: func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error) {
			return identity, nil
		},
	}
	defer cancel()
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: CheckpointIdentityRequest{Endpoint: identity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit}, ExpectedAlias: "model-alias"}
	if _, err := observeCheckpointManagedUnitLinux(canceled, req, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("final context cancellation did not fence association return: %v", err)
	}
	if collectCalls != 2 || verifyCalls != 2 {
		t.Fatalf("expected final collection and custody recheck before context fence: collect=%d custody=%d", collectCalls, verifyCalls)
	}
}

func TestCheckpointUnitIdentityLinuxActualObserverRejectsDuplicateListeners(t *testing.T) {
	f := newCheckpointIdentityFixture(t)
	tcpPath := filepath.Join(f.root, "net/tcp")
	row := checkpointFixtureTCPRow("0100007F", 8080, fixtureSocket)
	binding := CheckpointCustodyVerification{
		BindingSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), Endpoint: f.req.Endpoint,
		ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified",
		BootID: "00000000-0000-0000-0000-000000000001", PID: fixturePID, ProcessStartTicks: 123456,
		ListenerSocketInode: fixtureSocket, ExecutablePath: filepath.Clean(f.exe), ExecutableSHA256: f.req.ExpectedExecutableSHA256,
		ActualAlias: "fixture-alias", ArtifactPath: filepath.Clean(f.model), ArtifactDevice: f.device,
		ArtifactInode: f.inode, ArtifactSize: f.modelSize, ArtifactSHA256: f.req.ExpectedModelSHA256,
	}
	unit := checkpointUnitObservation{MainPID: fixturePID, InvocationID: "0123456789abcdef0123456789abcdef", ControlGroup: "/system.slice/llama-server.service", ActiveState: "active", SubState: "running", CgroupMembers: "/system.slice/llama-server.service"}
	verifyCalls := 0
	source := checkpointUnitLinuxSource{
		procRoot: f.root,
		collect: func(ctx context.Context, expectedPID int) (checkpointUnitObservation, error) {
			if err := ctx.Err(); err != nil {
				return checkpointUnitObservation{}, err
			}
			if expectedPID != 0 && expectedPID != fixturePID {
				return checkpointUnitObservation{}, errors.New("synthetic unit PID changed")
			}
			return unit, nil
		},
		verifyCustody: func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error) {
			verifyCalls++
			return binding, true, nil
		},
	}
	req := CheckpointUnitIdentityRequest{Custody: &CheckpointCustodyStore{}, Identity: f.req, ExpectedAlias: "fixture-alias"}
	association, err := observeCheckpointManagedUnitLinux(context.Background(), req, source)
	if err != nil {
		t.Fatalf("baseline synthetic fixture did not pass the actual local identity observer: %v", err)
	}
	if association.Identity.PID != fixturePID || association.Identity.ModelInode != f.inode || association.Custody.Nonce != binding.Nonce || verifyCalls != 2 {
		t.Fatalf("baseline observer result was incomplete or skipped custody recheck: association=%+v verifies=%d", association, verifyCalls)
	}
	verifyCalls = 0
	if err := os.WriteFile(tcpPath, []byte(row+strings.SplitN(row, "\n", 2)[1]), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = observeCheckpointManagedUnitLinux(context.Background(), req, source)
	const duplicateListenerError = "checkpoint endpoint has 2 matching listener sockets; expected exactly one"
	if err == nil || err.Error() != duplicateListenerError {
		t.Fatalf("duplicate listener did not produce its precise rejection; got %v, want %q", err, duplicateListenerError)
	}
	if verifyCalls != 1 {
		t.Fatalf("duplicate listener rejection reached the final custody stage unexpectedly: calls=%d", verifyCalls)
	}
}

func unixMkfifo(path string) error         { return unix.Mkfifo(path, 0600) }
func timeAfterUnitBound() <-chan time.Time { return time.After(100 * time.Millisecond) }
