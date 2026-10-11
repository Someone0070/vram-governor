//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"vram-governor/internal/checkpointgpuobserver"
)

func TestCheckpointRuntimeReadinessLoadingThenReadyAndFailures(t *testing.T) {
	const loading = `{"error":{"code":503,"message":"Loading model","type":"unavailable_error"}}`
	const ready = `{"status":"ok"}`
	t.Run("loading then ready", func(t *testing.T) {
		calls, childChecks := 0, 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health" {
				http.NotFound(w, r)
				return
			}
			calls++
			if calls == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(loading))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(ready))
		}))
		defer server.Close()
		port := server.Listener.Addr().(*net.TCPAddr).Port
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		err := waitCheckpointRuntimeReady(ctx, CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port}, func(context.Context) error {
			childChecks++
			return nil
		})
		if err != nil || calls != 2 || childChecks < 3 {
			t.Fatalf("loading->ready wait mismatch calls=%d childChecks=%d err=%v", calls, childChecks, err)
		}
	})
	t.Run("forever loading deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(loading))
		}))
		defer server.Close()
		port := server.Listener.Addr().(*net.TCPAddr).Port
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		defer cancel()
		err := waitCheckpointRuntimeReady(ctx, CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port}, func(context.Context) error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("loading deadline error=%v", err)
		}
	})
	for _, tc := range []struct {
		name string
		code int
		body string
	}{
		{"malformed loading", 503, `{"error":{"code":503,"message":"Loading model","type":"unavailable_error","extra":1}}`},
		{"fatal error", 500, `{"error":{"code":500,"message":"failed","type":"internal_error"}}`},
		{"wrong endpoint status", 404, `{"status":"ok"}`},
		{"ready duplicate key", 200, `{"status":"ok","status":"ok"}`},
		{"loading duplicate key", 503, `{"error":{"code":503,"code":503,"message":"Loading model","type":"unavailable_error"}}`},
		{"ready casefold field", 200, `{"Status":"ok"}`},
		{"ready mixed alias", 200, `{"status":"ok","Status":"ok"}`},
		{"loading casefold root", 503, `{"Error":{"code":503,"message":"Loading model","type":"unavailable_error"}}`},
		{"loading casefold nested", 503, `{"error":{"Code":503,"message":"Loading model","type":"unavailable_error"}}`},
		{"loading mixed nested alias", 503, `{"error":{"code":503,"Code":503,"message":"Loading model","type":"unavailable_error"}}`},
		{"trailing data", 200, `{"status":"ok"} {}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			port := server.Listener.Addr().(*net.TCPAddr).Port
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := waitCheckpointRuntimeReady(ctx, CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port}, func(context.Context) error { return nil }); err == nil {
				t.Fatal("malformed or fatal health response was retried or accepted")
			}
		})
	}
	t.Run("canceled or dead child", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(loading))
		}))
		defer server.Close()
		port := server.Listener.Addr().(*net.TCPAddr).Port
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := waitCheckpointRuntimeReady(ctx, CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port}, func(context.Context) error { return nil }); !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled wait error=%v", err)
		}
		if err := waitCheckpointRuntimeReady(context.Background(), CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: port}, func(context.Context) error { return errors.New("child died") }); err == nil || !strings.Contains(err.Error(), "child died") {
			t.Fatalf("dead child was not rejected before health retry: %v", err)
		}
	})
}

func TestCheckpointExecutableHashUsesBoundedNonblockingHeldFD(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "llama-server")
	content := []byte("controlled executable bytes")
	if err := os.WriteFile(path, content, 0500); err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	var initial unix.Stat_t
	if err := unix.Fstat(fd, &initial); err != nil {
		t.Fatal(err)
	}
	if got, err := hashCheckpointExecutableFD(context.Background(), fd, initial); err != nil {
		if !errors.Is(err, errCheckpointExecutableColdCache) && !errors.Is(err, errCheckpointExecutableNowaitUnsupported) {
			t.Fatalf("held-FD nonblocking verifier returned unexpected error: %v", err)
		}
	} else if !bytes.Equal(got, want[:]) {
		t.Fatalf("held-FD digest mismatch: got=%x want=%x", got, want)
	}
	pure := sha256.Sum256(content)
	if !bytes.Equal(pure[:], want[:]) {
		t.Fatal("independent positive digest control failed")
	}
	if err := verifyCheckpointExecutableHash(context.Background(), path, hex.EncodeToString(want[:])); err != nil && !errors.Is(err, errCheckpointExecutableColdCache) && !errors.Is(err, errCheckpointExecutableNowaitUnsupported) {
		t.Fatalf("production bounded verifier returned unexpected result: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifyCheckpointExecutableHash(ctx, path, hex.EncodeToString(want[:])); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled executable hash error=%v", err)
	}
	if err := verifyCheckpointExecutableHash(context.Background(), path, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong pinned executable digest was accepted")
	}
	link := filepath.Join(root, "server-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckpointExecutableHash(context.Background(), link, hex.EncodeToString(want[:])); err == nil {
		t.Fatal("symlink executable path was accepted")
	}
}

func TestCheckpointDeviceBindingRuntimeListingIsUniqueUnderMask(t *testing.T) {
	for _, raw := range []string{
		"CUDA0: NVIDIA device\n",
		"CUDA1: NVIDIA device\n",
		"CUDA0: first\nCUDA0: duplicate\n",
		"CUDA0 NVIDIA missing separator\n",
		"HIP0: unsupported backend\n",
		"",
	} {
		err := parseCheckpointRuntimeDeviceListing(raw, "CUDA0")
		if (raw == "CUDA0: NVIDIA device\n") != (err == nil) {
			t.Fatalf("runtime listing acceptance mismatch for %q: %v", raw, err)
		}
	}
}

func TestCheckpointDeviceBindingGPUProcessInventoryIsStrict(t *testing.T) {
	good := "241, GPU-01234567-89ab-cdef-0123-456789abcdef, 512\n242, GPU-11111111-2222-3333-4444-555555555555, 128\n"
	rows, err := parseCheckpointGPUProcesses(good)
	if err != nil || len(rows) != 2 || rows[0].PID != 241 || rows[0].UsedBytes != 512<<20 {
		t.Fatalf("valid fresh process inventory rejected: rows=%+v err=%v", rows, err)
	}
	for _, raw := range []string{
		"241, GPU-01234567-89ab-cdef-0123-456789abcdef, N/A\n",
		"241, GPU-01234567-89ab-cdef-0123-456789abcdef\n",
		"1, GPU-01234567-89ab-cdef-0123-456789abcdef, 512\n",
		"241, not-a-uuid, 512\n",
		"241, GPU-01234567-89ab-cdef-0123-456789abcdef, 0\n",
	} {
		if _, err := parseCheckpointGPUProcesses(raw); err == nil {
			t.Fatalf("malformed GPU process attribution accepted: %q", raw)
		}
	}
}

func TestCheckpointDeviceBindingPIDNamespaceIsFailClosed(t *testing.T) {
	for _, raw := range []string{
		"Name:\tworker\nNSpid:\t241\n",
		"Name:\tworker\nNSpid:\t3241 241\n",
	} {
		chain, err := parseCheckpointPIDNamespaceChain(raw, 241)
		if err != nil {
			t.Fatalf("well-formed namespace-relative PID chain rejected: %v", err)
		}
		if err := checkpointPIDNamespaceChainIsConsistent(chain); err != nil {
			t.Fatalf("valid namespace-relative PID chain failed consistency check: %v", err)
		}
	}
	for _, raw := range []string{
		"Name:\tworker\nNSpid:\t241 241\n",
		"Name:\tworker\nNSpid:\t241 bad\n",
		"Name:\tworker\n",
	} {
		if _, err := parseCheckpointPIDNamespaceChain(raw, 241); err == nil {
			t.Fatalf("ambiguous or missing PID namespace join accepted: %q", raw)
		}
	}
	if err := validateCheckpointInitialPIDNamespace(checkpointNSFSMagic, uint64(0x20000000), checkpointPIDNamespaceInitInode); err != nil {
		t.Fatalf("held initial PID namespace anchor rejected: %v", err)
	}
	for _, evidence := range [][3]uint64{
		{0, uint64(0x20000000), checkpointPIDNamespaceInitInode},
		{checkpointNSFSMagic, 0, checkpointPIDNamespaceInitInode},
		{checkpointNSFSMagic, uint64(0x20000000), 0xf0000001},
	} {
		if err := validateCheckpointInitialPIDNamespace(evidence[0], evidence[1], evidence[2]); err == nil {
			t.Fatalf("untrusted PID namespace descriptor evidence accepted: %+v", evidence)
		}
	}
	// A singleton NSpid chain is not host authority by itself: an ordinary
	// nested PID namespace receives a dynamic inode and must be rejected.
	chain, err := parseCheckpointPIDNamespaceChain("Name:\tworker\nNSpid:\t241\n", 241)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkpointPIDNamespaceChainIsConsistent(chain); err != nil {
		t.Fatal(err)
	}
	if err := validateCheckpointInitialPIDNamespace(checkpointNSFSMagic, uint64(0x20000000), 0xf0000001); err == nil {
		t.Fatal("single-value NSpid chain plus dynamic namespace inode was treated as initial namespace authority")
	}
}

func TestCheckpointDeviceBindingChildPlacementObservationBoundedJoin(t *testing.T) {
	const pid = 241
	plan := checkpointPlacementFixture()
	validSource := func() checkpointChildPlacementSource {
		startCalls := 0
		return checkpointChildPlacementSource{
			processStart: func(context.Context, int) (uint64, error) {
				startCalls++
				return 987654, nil
			},
			pidNamespace:   func(context.Context, int) error { return nil },
			namespaceRoute: func(context.Context, int) (bool, error) { return false, nil },
			gpuProcesses: func(context.Context) ([]checkpointGPUProcess, error) {
				return []checkpointGPUProcess{{PID: pid, UUID: plan.Placement.PhysicalIdentity, UsedBytes: 2 << 20}}, nil
			},
			devices: func(context.Context) ([]checkpointGPUDevice, error) {
				return []checkpointGPUDevice{{UUID: plan.Placement.PhysicalIdentity, PCI: "00000000:01:00.0"}}, nil
			},
			hostRSS: func(context.Context, int) (int64, error) { return 1 << 30, nil },
			runtimeLog: func() ([]byte, error) {
				return []byte("load_tensors: offloaded 33/33 layers to GPU\n"), nil
			},
		}
	}
	positive, err := observeCheckpointChildPlacementWithSource(context.Background(), plan, pid, 987654, validSource())
	if err != nil || positive.GPUBytes != 2<<20 || positive.HostRSS != 1<<30 || positive.LayersGPU != 33 || positive.LayersTotal != 33 {
		t.Fatalf("bounded current-child placement join failed: evidence=%+v err=%v", positive, err)
	}

	faults := []struct {
		name   string
		mutate func(*checkpointChildPlacementSource)
	}{
		{"missing gpu attribution", func(source *checkpointChildPlacementSource) {
			source.gpuProcesses = func(context.Context) ([]checkpointGPUProcess, error) { return nil, nil }
		}},
		{"extra gpu attribution", func(source *checkpointChildPlacementSource) {
			source.gpuProcesses = func(context.Context) ([]checkpointGPUProcess, error) {
				return []checkpointGPUProcess{
					{PID: pid, UUID: plan.Placement.PhysicalIdentity, UsedBytes: 2 << 20},
					{PID: pid, UUID: "GPU-11111111-2222-3333-4444-555555555555", UsedBytes: 1 << 20},
				}, nil
			}
		}},
		{"wrong physical gpu", func(source *checkpointChildPlacementSource) {
			source.gpuProcesses = func(context.Context) ([]checkpointGPUProcess, error) {
				return []checkpointGPUProcess{{PID: pid, UUID: "GPU-11111111-2222-3333-4444-555555555555", UsedBytes: 2 << 20}}, nil
			}
		}},
		{"unanchored pid namespace", func(source *checkpointChildPlacementSource) {
			source.pidNamespace = func(context.Context, int) error { return errors.New("unanchored test namespace") }
		}},
		{"malformed gpu inventory", func(source *checkpointChildPlacementSource) {
			source.gpuProcesses = func(context.Context) ([]checkpointGPUProcess, error) {
				return nil, errors.New("malformed GPU process inventory")
			}
		}},
		{"missing full offload evidence", func(source *checkpointChildPlacementSource) {
			source.runtimeLog = func() ([]byte, error) { return []byte("load_tensors: offloaded 32/33 layers to GPU\n"), nil }
		}},
		{"changed child incarnation", func(source *checkpointChildPlacementSource) {
			calls := 0
			source.processStart = func(context.Context, int) (uint64, error) {
				calls++
				if calls == 1 {
					return 987654, nil
				}
				return 987655, nil
			}
		}},
	}
	for _, fault := range faults {
		t.Run(fault.name, func(t *testing.T) {
			source := validSource()
			fault.mutate(&source)
			if evidence, err := observeCheckpointChildPlacementWithSource(context.Background(), plan, pid, 987654, source); err == nil {
				t.Fatalf("invalid bounded placement observation reached READY evidence: %+v", evidence)
			}
		})
	}
	t.Run("before ready abort retains ownership", func(t *testing.T) {
		source := validSource()
		source.gpuProcesses = func(context.Context) ([]checkpointGPUProcess, error) { return nil, nil }
		readyCalls, releaseCalls := 0, 0
		steps := checkpointFixedStartupSteps{
			commit:  func(context.Context) error { return nil },
			mainPID: func(context.Context, int) error { return nil },
			barrier: func(context.Context) error { return nil },
			join: func(ctx context.Context) error {
				_, err := observeCheckpointChildPlacementWithSource(ctx, plan, pid, 987654, source)
				return err
			},
			ready: func(context.Context) error { readyCalls++; return nil },
		}
		if err := runCheckpointFixedStartupSteps(context.Background(), pid, steps); err == nil || readyCalls != 0 {
			t.Fatalf("failed placement reached READY: err=%v ready calls=%d", err, readyCalls)
		}
		if err := cleanupCheckpointFixedOwnedChild(context.Background(), func(context.Context) (bool, error) {
			return false, errors.New("reap outcome uncertain")
		}, func(context.Context) error {
			releaseCalls++
			return nil
		}); err == nil || releaseCalls != 0 {
			t.Fatalf("uncertain failed-start cleanup released ownership: err=%v releases=%d", err, releaseCalls)
		}
	})
}

func TestCheckpointChildPlacementNestedObserverAndNoFallback(t *testing.T) {
	const pid = 241
	plan := checkpointPlacementFixture()
	startCalls := 0
	directCalls, bridgeCalls := 0, 0
	source := checkpointChildPlacementSource{
		processStart:   func(context.Context, int) (uint64, error) { startCalls++; return 987654, nil },
		pidNamespace:   func(context.Context, int) error { directCalls++; return nil },
		namespaceRoute: func(context.Context, int) (bool, error) { return true, nil },
		gpuProcesses: func(context.Context) ([]checkpointGPUProcess, error) {
			directCalls++
			return nil, errors.New("direct inventory must not run for nested worker")
		},
		devices: func(context.Context) ([]checkpointGPUDevice, error) {
			return []checkpointGPUDevice{{UUID: plan.Placement.PhysicalIdentity, PCI: "00000000:01:00.0"}}, nil
		},
		nestedAttribution: func(_ context.Context, gotPID int, start uint64, gotPlan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {
			bridgeCalls++
			if gotPID != pid || start != 987654 || gotPlan.Placement != plan.Placement || placement.ChildMaskUUID != plan.Placement.PhysicalIdentity {
				t.Fatal("nested adapter did not receive exact worker and fixed plan")
			}
			response := checkpointgpuobserver.Response{GPU: checkpointgpuobserver.GPUProcess{PID: 912, UUID: placement.ChildMaskUUID, Bytes: 2 << 20}, GPUUUID: placement.ChildMaskUUID, GPUPCI: "00000000:01:00.0"}
			return checkpointHostGPUObservation{Bytes: 2 << 20, Response: response}, nil
		},
		hostRSS:    func(context.Context, int) (int64, error) { return 1 << 30, nil },
		runtimeLog: func() ([]byte, error) { return []byte("load_tensors: offloaded 33/33 layers to GPU\n"), nil },
	}
	evidence, err := observeCheckpointChildPlacementWithSource(context.Background(), plan, pid, 987654, source)
	if err != nil || evidence.GPUBytes != 2<<20 || bridgeCalls != 1 || directCalls != 0 || startCalls != 2 {
		t.Fatalf("nested attribution did not use only the host bridge: evidence=%+v bridge=%d direct=%d starts=%d err=%v", evidence, bridgeCalls, directCalls, startCalls, err)
	}
	source.nestedAttribution = func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {
		bridgeCalls++
		return checkpointHostGPUObservation{}, errors.New("fixed bridge unavailable")
	}
	if _, err := observeCheckpointChildPlacementWithSource(context.Background(), plan, pid, 987654, source); err == nil || directCalls != 0 {
		t.Fatal("nested bridge failure fell back to the initial-namespace process inventory")
	}
}
