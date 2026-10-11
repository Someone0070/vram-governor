//go:build linux

package checkpointgpuobserver

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestObserverNamespaceTypeFromHeldCurrentPIDDescriptor(t *testing.T) {
	fd, err := unix.Open("/proc/self/ns/pid", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open current PID namespace: %v", err)
	}
	defer unix.Close(fd)
	namespace, err := namespaceFromFD(fd)
	if err != nil {
		t.Fatalf("read held current PID namespace: %v", err)
	}
	if namespace.Filesystem != observerNSFSMagic || namespace.NamespaceType != uint64(unix.CLONE_NEWPID) || namespace.Inode == 0 {
		t.Fatalf("unexpected current PID namespace identity: %+v", namespace)
	}

	ordinary := filepath.Join(t.TempDir(), "not-a-namespace")
	if err := os.WriteFile(ordinary, []byte("ordinary file"), 0600); err != nil {
		t.Fatal(err)
	}
	ordinaryFD, err := unix.Open(ordinary, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ordinaryFD)
	if _, err := namespaceFromFD(ordinaryFD); err == nil {
		t.Fatal("ordinary file was accepted as a held namespace")
	}
}

func TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority(t *testing.T) {
	config := ObserverConfig{
		Version: ProtocolVersion, SocketGID: 1200,
		PeerAuthorities: []PeerAuthority{
			{Role: "node-agent", UID: 1100, ExecutablePath: "/usr/sbin/vram-node-agent", ExecutableSHA256: strings.Repeat("a", 64), CgroupRoots: []string{"/ct.slice"}},
			{Role: "fixed-supervisor", UID: 0, ExecutablePath: "/usr/libexec/vram-checkpoint-launcher", ExecutableSHA256: strings.Repeat("b", 64), CgroupRoots: []string{"/ct.slice"}},
		},
		Containers: []ContainerAuthority{{CgroupRoot: "/ct.slice", NodeAgentUID: 1100, NodeAgentExecutablePath: "/usr/sbin/vram-node-agent", NodeAgentExecutableSHA256: strings.Repeat("a", 64)}},
	}
	if err := validateObserverConfig(config); err != nil {
		t.Fatalf("complete root-approved roles rejected: %v", err)
	}
	withLocalObserver := config
	withLocalObserver.PeerAuthorities = append(append([]PeerAuthority(nil), config.PeerAuthorities...), PeerAuthority{Role: "local-observer", UID: 0, ExecutablePath: "/usr/libexec/vram-checkpoint-local-observer", ExecutableSHA256: strings.Repeat("c", 64), CgroupRoots: []string{"/ct.slice"}})
	if err := validateObserverConfig(withLocalObserver); err != nil {
		t.Fatalf("optional exact root local-observer role rejected: %v", err)
	}
	for name, mutate := range map[string]func(*ObserverConfig){
		"local observer wrong UID": func(candidate *ObserverConfig) { candidate.PeerAuthorities[2].UID = 1200 },
		"duplicate local observer role": func(candidate *ObserverConfig) { candidate.PeerAuthorities = append(candidate.PeerAuthorities, candidate.PeerAuthorities[2]) },
		"local observer executable swap": func(candidate *ObserverConfig) {
			candidate.PeerAuthorities[2].ExecutablePath = candidate.PeerAuthorities[1].ExecutablePath
			candidate.PeerAuthorities[2].ExecutableSHA256 = candidate.PeerAuthorities[1].ExecutableSHA256
		},
		"node agent changed to root only": func(candidate *ObserverConfig) { candidate.PeerAuthorities[0].UID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := withLocalObserver
			candidate.PeerAuthorities = append([]PeerAuthority(nil), withLocalObserver.PeerAuthorities...)
			mutate(&candidate)
			if err := validateObserverConfig(candidate); err == nil {
				t.Fatal("wrong UID, duplicate role, or swapped executable authority was accepted")
			}
		})
	}
	overlappingRootRole := withLocalObserver
	overlappingRootRole.PeerAuthorities = append([]PeerAuthority(nil), withLocalObserver.PeerAuthorities...)
	overlappingRootRole.PeerAuthorities[2].ExecutablePath = withLocalObserver.PeerAuthorities[1].ExecutablePath
	overlappingRootRole.PeerAuthorities[2].ExecutableSHA256 = withLocalObserver.PeerAuthorities[1].ExecutableSHA256
	if err := validateObserverConfig(overlappingRootRole); err == nil {
		t.Fatal("overlapping root local-observer and supervisor authority was accepted")
	}
	missingRoot := config
	missingRoot.PeerAuthorities = config.PeerAuthorities[:1]
	if err := validateObserverConfig(missingRoot); err == nil {
		t.Fatal("node-agent-only peer allowlist was accepted")
	}
	badPath := config
	badPath.Containers = []ContainerAuthority{{CgroupRoot: "/ct.slice/../other", NodeAgentUID: 1100, NodeAgentExecutableSHA256: strings.Repeat("a", 64)}}
	if err := validateObserverConfig(badPath); err == nil {
		t.Fatal("traversing cgroup root was accepted")
	}
	badDigest := config
	badDigest.PeerAuthorities = append([]PeerAuthority(nil), config.PeerAuthorities...)
	badDigest.PeerAuthorities[0].ExecutableSHA256 = ""
	if err := validateObserverConfig(badDigest); err == nil {
		t.Fatal("UID-only peer authority was accepted")
	}
}

func TestObserverPeerNeedsExecutableAndHostCgroupAuthority(t *testing.T) {
	authority := PeerAuthority{Role: "node-agent", UID: 1100, ExecutablePath: "/usr/sbin/vram-node-agent", ExecutableSHA256: strings.Repeat("a", 64), CgroupRoots: []string{"/ct.slice"}}
	peer := &heldProcess{value: Process{PID: 900, Cgroup: "/ct.slice/node-agent.scope"}, exe: "/usr/sbin/vram-node-agent", exeSHA256: strings.Repeat("a", 64)}
	if !observerPeerMatches(peer, 1100, authority) {
		t.Fatal("exact peer authority did not match")
	}
	for name, mutate := range map[string]func(*heldProcess, *PeerAuthority, *uint32){
		"uid":             func(_ *heldProcess, _ *PeerAuthority, uid *uint32) { *uid = 1101 },
		"executable":      func(peer *heldProcess, _ *PeerAuthority, _ *uint32) { peer.exeSHA256 = strings.Repeat("c", 64) },
		"executable path": func(peer *heldProcess, _ *PeerAuthority, _ *uint32) { peer.exe = "/tmp/copied-agent" },
		"cgroup": func(peer *heldProcess, _ *PeerAuthority, _ *uint32) {
			peer.value.Cgroup = "/other.slice/node-agent.scope"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *peer
			changedAuthority := authority
			uid := authority.UID
			mutate(&changed, &changedAuthority, &uid)
			if observerPeerMatches(&changed, uid, changedAuthority) {
				t.Fatal("peer identity matched on UID alone or wrong role authority")
			}
		})
	}
}

func TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRoles(t *testing.T) {
	const executable = "/usr/libexec/vram-checkpoint-local-observer"
	const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	credentials := &unix.Ucred{Pid: 900, Uid: 0, Gid: 0}
	peer := &heldProcess{value: Process{PID: 900, Cgroup: "/ct.slice/observer.scope"}, pidfd: -1, nsfd: -1,
		exe: executable, uid: 0, exeSHA256: digest}
	open := func(_ context.Context, pid int) (*heldProcess, error) {
		if pid != int(credentials.Pid) {
			return nil, errors.New("unexpected test peer PID")
		}
		copy := *peer
		return &copy, nil
	}
	config := ObserverConfig{PeerAuthorities: []PeerAuthority{{Role: "local-observer", UID: 0, ExecutablePath: executable,
		ExecutableSHA256: digest, CgroupRoots: []string{"/ct.slice"}}}, Containers: []ContainerAuthority{{CgroupRoot: "/ct.slice",
		NodeAgentUID: 1100, NodeAgentExecutablePath: "/usr/sbin/vram-node-agent", NodeAgentExecutableSHA256: strings.Repeat("b", 64)}}}
	accepted, role, container, err := authorizeObserverPeerUsing(context.Background(), credentials, config, open)
	if err != nil || accepted == nil || role.Role != "local-observer" || container.CgroupRoot != "/ct.slice" {
		t.Fatalf("otherwise-valid single caller role was not authorized: role=%+v container=%+v err=%v", role, container, err)
	}
	accepted.close()
	config.PeerAuthorities = append(config.PeerAuthorities, PeerAuthority{Role: "fixed-supervisor", UID: 0, ExecutablePath: executable,
		ExecutableSHA256: digest, CgroupRoots: []string{"/ct.slice"}})
	if accepted, _, _, err := authorizeObserverPeerUsing(context.Background(), credentials, config, open); err == nil || accepted != nil || err.Error() != "Unix peer matches multiple fixed caller roles" {
		if accepted != nil {
			accepted.close()
		}
		t.Fatalf("otherwise-valid multiple-role match was not rejected by the ambiguity predicate: peer=%v err=%v", accepted, err)
	}
}

func TestObserverPeerContainerSelectionRequiresUniqueOverlap(t *testing.T) {
	for _, role := range []string{"node_agent", "fixed_supervisor", "local_observer"} {
		t.Run(role, func(t *testing.T) {
			uid, executable, digest := uint32(1100), "/usr/sbin/vram-node-agent", strings.Repeat("a", 64)
			if role == "fixed_supervisor" || role == "local_observer" {
				uid, executable, digest = 0, "/usr/libexec/vram-checkpoint-launcher", strings.Repeat("b", 64)
				if role == "local_observer" {
					executable, digest = "/usr/libexec/vram-checkpoint-local-observer", strings.Repeat("c", 64)
				}
			}
			authority := PeerAuthority{Role: strings.ReplaceAll(role, "_", "-"), UID: uid, ExecutablePath: executable, ExecutableSHA256: digest, CgroupRoots: []string{"/ct.slice"}}
			peer := &heldProcess{value: Process{PID: 900, Cgroup: "/ct.slice/container.scope/worker.scope"}, exe: executable, uid: uid, exeSHA256: digest}
			container := func(root string) ContainerAuthority {
				return ContainerAuthority{CgroupRoot: root, NodeAgentUID: 1100, NodeAgentExecutablePath: "/usr/sbin/vram-node-agent", NodeAgentExecutableSHA256: strings.Repeat("a", 64)}
			}
			for _, test := range []struct {
				name       string
				containers []ContainerAuthority
				ambiguous  bool
			}{
				{name: "single_match", containers: []ContainerAuthority{container("/ct.slice")}},
				{name: "disjoint_sibling", containers: []ContainerAuthority{container("/ct.slice"), container("/other.slice")}},
				{name: "overlap_rejected", containers: []ContainerAuthority{container("/ct.slice"), container("/ct.slice/container.scope")}, ambiguous: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					selected, err := selectObserverPeerContainer(peer, authority, test.containers)
					if test.ambiguous {
						if err == nil {
							t.Fatal("overlapping root container authorities were accepted")
						}
						return
					}
					if err != nil || selected.CgroupRoot != "/ct.slice" {
						t.Fatalf("unique matching root was rejected or changed: %+v %v", selected, err)
					}
				})
			}
		})
	}
}

func TestHostNSpidParserRetainsRepeatedIDsAcrossNamespaceLevels(t *testing.T) {
	chain, err := parseNSpidStatus([]byte("Name:\tworker\nNSpid:\t937\t37\t37\n"))
	if err != nil || len(chain) != 3 || chain[1] != chain[2] {
		t.Fatalf("valid repeated namespace IDs rejected: %v %v", chain, err)
	}
	for _, raw := range [][]byte{
		[]byte("Name:\tworker\n"),
		[]byte("NSpid:\t937\nNSpid:\t938\n"),
		[]byte("NSpid:\t937\t0\n"),
		[]byte("NSpid:\t937\t" + strings.Repeat("1\t", MaxNSpidDepth) + "2\n"),
	} {
		if _, err := parseNSpidStatus(raw); err == nil {
			t.Fatalf("invalid NSpid chain was accepted: %q", raw)
		}
	}
}

func TestGPUInventoryParserAndUniqueWorkerJoin(t *testing.T) {
	const uuid = "GPU-00000000-0000-0000-0000-000000000001"
	devices, err := parseGPUDevices(uuid + ", 0000:01:00.0\n")
	if err != nil || len(devices) != 1 {
		t.Fatalf("valid GPU inventory rejected: %+v %v", devices, err)
	}
	for _, raw := range []string{
		uuid + ", 0000:01:00.0\n" + uuid + ", 0000:02:00.0\n",
		"GPU-bad, 0000:01:00.0\n",
		uuid + ", 0000:01:00.0, extra\n",
	} {
		if _, err := parseGPUDevices(raw); err == nil {
			t.Fatalf("ambiguous physical inventory was accepted: %q", raw)
		}
	}
	rows, err := parseGPUProcesses("937, " + uuid + ", 1024\n938, " + uuid + ", 512\n")
	if err != nil {
		t.Fatal(err)
	}
	joined, err := joinWorkerGPUProcess(rows, 937, uuid)
	if err != nil || joined.Bytes != 1024<<20 {
		t.Fatalf("unique worker row rejected: %+v %v", joined, err)
	}
	for name, changed := range map[string][]GPUProcess{
		"absent":    rows[1:],
		"duplicate": append(append([]GPUProcess(nil), rows...), rows[0]),
		"wrong GPU": {{PID: 937, UUID: "GPU-00000000-0000-0000-0000-000000000099", Bytes: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := joinWorkerGPUProcess(changed, 937, uuid); err == nil {
				t.Fatal("absent, duplicate, or wrong-GPU worker row was accepted")
			}
		})
	}
}
