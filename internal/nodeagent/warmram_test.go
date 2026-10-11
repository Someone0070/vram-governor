package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testWarmPin struct {
	closed           bool
	closeErr         error
	resident, locked int64
}

func (p *testWarmPin) Close() error         { p.closed = true; return p.closeErr }
func (p *testWarmPin) ResidentBytes() int64 { return p.resident }
func (p *testWarmPin) LockedBytes() int64   { return p.locked }

func testWarmRAMManager(t *testing.T, pressure float64) (*WarmRAMManager, string) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "model.gguf")
	if err := os.WriteFile(path, []byte("verified model bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMTotalBytes: 1 << 30, RAMReserveBytes: 1 << 20, RAMHardCapBytes: 1 << 29, MaxWarmBytes: 1 << 20, MemlockLimitBytes: 1 << 20, CurrentRAMBytes: func() (int64, error) { return 1, nil }, AvailableRAMBytes: func() (int64, error) { return 1 << 29, nil }, PressurePercent: func() (float64, error) { return pressure, nil }})
	return manager, path
}

func TestWarmRAMPinsResidentModelAndConfirmsReleasedVRAM(t *testing.T) {
	manager, path := testWarmRAMManager(t, 0)
	if !warmRAMOSSupported() {
		if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path}); err == nil {
			t.Fatal("unsupported platform claimed warm residency")
		}
		return
	}
	released := false
	result, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path,
		ReleaseVRAM: func(context.Context) error { released = true; return nil }, ConfirmReleased: func(context.Context) (bool, error) { return released, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.ResidentBytes < result.Bytes || result.LockedBytes < result.Bytes || !result.VRAMReleased || result.Oracle != "mincore+mlock" {
		t.Fatalf("unverified warm result: %+v", result)
	}
	if err := manager.ReleaseModel("model"); err != nil {
		t.Fatal(err)
	}
}

func TestWarmRAMRejectsNonCanonicalAndPressure(t *testing.T) {
	manager, path := testWarmRAMManager(t, 90)
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err == nil {
		t.Fatal("pressure refusal missing")
	}
	manager, path = testWarmRAMManager(t, 0)
	outside := filepath.Join(t.TempDir(), "outside.gguf")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "outside", Path: outside, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err == nil {
		t.Fatal("path outside allowlist was accepted")
	}
	link := filepath.Join(filepath.Dir(path), "link.gguf")
	if err := os.Symlink(path, link); err != nil {
		t.Logf("symlinks unavailable; canonical-path check covered by outside path: %v", err)
	} else if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "link", Path: link, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err == nil {
		t.Fatal("symlink path was accepted")
	}
}

func TestWarmRAMRollsBackWhenReleasedVRAMIsUnconfirmed(t *testing.T) {
	manager, path := testWarmRAMManager(t, 0)
	if !warmRAMOSSupported() {
		return
	}
	restored := false
	_, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return false, nil }, RestoreVRAM: func(context.Context) error { restored = true; return nil }})
	if err == nil || !restored || len(manager.Snapshot()) != 0 {
		t.Fatalf("failed warm transition leaked state: err=%v restored=%t snapshot=%v", err, restored, manager.Snapshot())
	}
}

func TestWarmRAMRefusesObservedOOMPressure(t *testing.T) {
	manager, path := testWarmRAMManager(t, 0)
	manager.policy.OOMEvents = func() (int64, error) { return 2, nil }
	manager.policy.OOMEventsBaseline = 1
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err == nil {
		t.Fatal("OOM pressure was not refused")
	}
}

func TestWarmRAMUnsupportedFailsClosed(t *testing.T) {
	manager := NewWarmRAMManager(WarmRAMPolicy{RAMHardCapBytes: 1 << 30, RAMReserveBytes: 1})
	if manager.Supported() {
		t.Fatal("unsupported platform advertised warm RAM")
	}
}

func TestWarmRAMKnownBrokenControl(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) { return warmFileIdentity{Size: 5}, nil },
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return &testWarmPin{resident: 5, locked: 0}, warmFileIdentity{Size: 5}, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 90, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "page-cache" },
	})
	_, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }})
	if err == nil || !strings.Contains(err.Error(), "independently verified") || len(manager.Snapshot()) != 0 {
		t.Fatalf("known broken page-cache fixture was accepted: err=%v snapshot=%v", err, manager.Snapshot())
	}
}

func TestWarmRAMValidationCloseFailureRetainsCleanupHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("d", 64)
	pin := &testWarmPin{resident: 5, locked: 0, closeErr: errors.New("validation close sentinel")}
	marked := 0
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100, MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			return warmFileIdentity{Size: 5, Hash: fingerprint}, nil
		},
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return pin, warmFileIdentity{Size: 5, Hash: fingerprint}, nil
		},
		Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" }})
	_, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "target", Model: "model", Path: path, ExpectedFingerprint: fingerprint, MarkSideEffect: func() { marked++ },
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }})
	if err == nil || marked == 0 {
		t.Fatalf("validation failure did not report local cleanup side effect: err=%v marks=%d", err, marked)
	}
	rows := manager.Snapshot()
	if len(rows) != 1 || rows[0].Verified || rows[0].VRAMReleased {
		t.Fatalf("validation close failure was not retained unverified: %+v", rows)
	}
	pin.closeErr = nil
	if err := manager.ReleaseModelFor("target", "model"); err != nil || manager.HasEntryFor("target", "model") {
		t.Fatalf("validation cleanup retry failed: err=%v entry=%v", err, manager.HasEntryFor("target", "model"))
	}
}

func TestWarmRAMLRUCloseFailureInvokesSideEffectAndRetainsVictim(t *testing.T) {
	root := t.TempDir()
	victimPath, requestedPath := filepath.Join(root, "victim.bin"), filepath.Join(root, "requested.bin")
	for _, path := range []string{victimPath, requestedPath} {
		if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	identities := map[string]warmFileIdentity{victimPath: {Size: 5, Hash: strings.Repeat("e", 64)}, requestedPath: {Size: 5, Hash: strings.Repeat("f", 64)}}
	victimPin := &testWarmPin{resident: 5, locked: 5}
	requestedPin := &testWarmPin{resident: 5, locked: 5}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 5, MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(path string, _ []string) (warmFileIdentity, error) { return identities[path], nil },
		PinFile: func(path string, _ []string, identity warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			if path == victimPath {
				return victimPin, identity, nil
			}
			return requestedPin, identity, nil
		}, Snapshot: func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" }})
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "target", Model: "victim", Path: victimPath, ExpectedFingerprint: identities[victimPath].Hash,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatalf("victim warm failed: %v", err)
	}
	victimPin.closeErr = errors.New("victim close sentinel")
	marked := 0
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "target", Model: "requested", Path: requestedPath, ExpectedFingerprint: identities[requestedPath].Hash, MarkSideEffect: func() { marked++ },
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err == nil || marked == 0 {
		t.Fatalf("LRU close failure did not propagate side effect: err=%v marks=%d", err, marked)
	}
	if !manager.HasEntryFor("target", "victim") || manager.IsVerifiedFor("target", "victim") {
		t.Fatal("failed LRU victim was not retained as unverified cleanup state")
	}
	victimPin.closeErr = nil
	if err := manager.ReleaseModelFor("target", "victim"); err != nil || manager.HasEntryFor("target", "victim") {
		t.Fatalf("LRU victim cleanup retry failed: err=%v entry=%v", err, manager.HasEntryFor("target", "victim"))
	}
}

func TestWarmRAMDeterministicPressureRollbackAndCleanup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	makeManager := func(pressure float64, pin *testWarmPin) *WarmRAMManager {
		return NewWarmRAMManager(WarmRAMPolicy{
			AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
			MemlockLimitBytes: 100, PressureRefusalPercent: 80,
			OpenIdentity: func(string, []string) (warmFileIdentity, error) { return warmFileIdentity{Size: 5}, nil },
			PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
				return pin, warmFileIdentity{Size: 5}, nil
			},
			Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 90, 0, 0, pressure, nil },
			MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
		})
	}
	if _, err := makeManager(90, &testWarmPin{resident: 5, locked: 5}).OffloadModel(context.Background(), WarmRAMRequest{Model: "pressure", Path: path,
		ReleaseVRAM: func(context.Context) error { t.Fatal("pressure path released VRAM"); return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); !errors.Is(err, ErrWarmRAMPressure) {
		t.Fatalf("pressure admission was not refused: %v", err)
	}
	restored := false
	manager := makeManager(0, &testWarmPin{resident: 5, locked: 5})
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "rollback", Path: path,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return false, nil }, RestoreVRAM: func(context.Context) error { restored = true; return nil }}); err == nil || !restored || len(manager.Snapshot()) != 0 {
		t.Fatalf("rollback did not restore and clear state: err=%v restored=%t", err, restored)
	}
	pin := &testWarmPin{resident: 5, locked: 5, closeErr: errors.New("cleanup sentinel")}
	manager = makeManager(0, pin)
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "cleanup", Path: path,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatal(err)
	}
	if err := manager.ReleaseModel("cleanup"); err == nil || len(manager.Snapshot()) != 1 || manager.Snapshot()[0].Verified {
		t.Fatalf("cleanup failure was advertised as verified: %v %v", err, manager.Snapshot())
	}
}

func TestWarmRAMPlatformNeutralParsersFailClosed(t *testing.T) {
	if total, available, err := parseMemInfoBytes([]byte("MemTotal: 1024 kB\nMemAvailable: 512 kB\n")); err != nil || total != 1024*1024 || available != 512*1024 {
		t.Fatalf("valid meminfo rejected: %d %d %v", total, available, err)
	}
	for _, body := range []string{"MemTotal: nope kB\nMemAvailable: 1 kB", "MemTotal: 1 MB\nMemAvailable: 1 kB", "MemTotal: 1 kB\nMemAvailable: 2 kB"} {
		if _, _, err := parseMemInfoBytes([]byte(body)); err == nil {
			t.Fatalf("invalid meminfo accepted: %q", body)
		}
	}
	if pressure, err := parsePSIBytes([]byte("some avg10=12.5 avg60=1 avg300=1 total=1\n")); err != nil || pressure != 12.5 {
		t.Fatalf("valid PSI rejected: %v %v", pressure, err)
	}
	for _, body := range []string{"some avg10=NaN avg60=1 avg300=1 total=1", "some avg10=101 avg60=1 avg300=1 total=1", "full avg10=1 avg60=1 avg300=1 total=1"} {
		if _, err := parsePSIBytes([]byte(body)); err == nil {
			t.Fatalf("invalid PSI accepted: %q", body)
		}
	}
	if count, err := parseOOMBytes([]byte("oom 2\noom_kill 3\noom_group_kill 4\n")); err != nil || count != 9 {
		t.Fatalf("valid OOM counters rejected: %d %v", count, err)
	}
	for _, body := range []string{"oomish 3", "oom nope", "oom_group_kill nope", "oom 1\noom_group_kill", "memory 1", "oom 1\noom 2"} {
		if _, err := parseOOMBytes([]byte(body)); err == nil {
			t.Fatalf("invalid OOM counters accepted: %q", body)
		}
	}
}

func TestWarmRAMRejectsPageCacheWithLockedBytes(t *testing.T) {
	if err := validateWarmRAMResult(WarmRAMResult{Verified: true, Bytes: 1, ResidentBytes: 1, LockedBytes: 1, VRAMReleased: true, Oracle: "page-cache"}); err == nil {
		t.Fatal("page-cache oracle with locked bytes was accepted")
	}
}

func TestWarmRAMRejectsUnlockedBytesWithValidOracle(t *testing.T) {
	if err := validateWarmRAMResult(WarmRAMResult{Verified: true, Bytes: 1, ResidentBytes: 1, LockedBytes: 0, VRAMReleased: true, Oracle: "mincore+mlock"}); err == nil {
		t.Fatal("valid oracle with zero locked bytes was accepted")
	}
}

func TestWarmRAMHotReloadInvalidatesWarmClaim(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	identity := warmFileIdentity{Dev: 1, Ino: 2, Size: 5, Mtime: 3, Hash: fingerprint}
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) { return identity, nil },
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return &testWarmPin{resident: 5, locked: 5}, identity, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 90, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
	})
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-runtime", Model: "model", Path: path, ExpectedFingerprint: fingerprint, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatal(err)
	}
	if !manager.IsVerifiedFor("node-runtime", "model") {
		t.Fatal("initial warm claim was not verified")
	}
	identity.Hash = strings.Repeat("b", 64)
	if manager.IsVerifiedFor("node-runtime", "model") {
		t.Fatal("hot-reloaded file retained a verified warm claim")
	}
	marked := 0
	if _, err := manager.UpdateProtectionFor("node-runtime", "model", 0, true, func() { marked++ }); err == nil || marked != 1 {
		t.Fatalf("protect invalidation did not propagate side-effect marker: err=%v marks=%d", err, marked)
	}
	rows := manager.Snapshot()
	if len(rows) != 1 || rows[0].Verified || rows[0].VRAMReleased {
		t.Fatalf("hot reload did not leave explicit unverified state: %+v", rows)
	}
}

func TestWarmRAMHeadroomDoesNotDoubleCountExistingPinnedBytes(t *testing.T) {
	root := t.TempDir()
	firstPath, secondPath := filepath.Join(root, "first.bin"), filepath.Join(root, "second.bin")
	if err := os.WriteFile(firstPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	identities := map[string]warmFileIdentity{firstPath: {Size: 5, Hash: strings.Repeat("1", 64)}, secondPath: {Size: 6, Hash: strings.Repeat("2", 64)}}
	manager := NewWarmRAMManager(WarmRAMPolicy{AllowedRoots: []string{root}, RAMHardCapBytes: 12, RAMReserveBytes: 1, MaxWarmBytes: 12, MemlockLimitBytes: 12, PressureRefusalPercent: 90,
		OpenIdentity: func(path string, _ []string) (warmFileIdentity, error) { return identities[path], nil },
		PinFile: func(path string, _ []string, identity warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return &testWarmPin{resident: identity.Size, locked: identity.Size}, identity, nil
		},
		Snapshot: func() (int64, int64, int64, int64, float64, error) { return 0, 100, 0, 0, 0, nil }, MemlockLimit: func() (int64, error) { return 12, nil }, Oracle: func() string { return "mincore+mlock" }})
	for _, item := range []struct{ model, path, hash string }{{"first", firstPath, identities[firstPath].Hash}, {"second", secondPath, identities[secondPath].Hash}} {
		if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "node-runtime", Model: item.model, Path: item.path, ExpectedFingerprint: item.hash, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
			t.Fatalf("existing-pin headroom was double-counted for %s: %v", item.model, err)
		}
	}
}

func TestWarmRAMTargetScopedIdentityAndReverification(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			return warmFileIdentity{Size: 5, Hash: fingerprint}, nil
		},
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return &testWarmPin{resident: 5, locked: 5}, warmFileIdentity{Size: 5, Hash: fingerprint}, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 90, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
	})
	for _, target := range []string{"target-a", "target-b"} {
		if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: target, Model: "model", Path: path, ExpectedFingerprint: fingerprint,
			ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
			t.Fatal(err)
		}
	}
	if !manager.IsVerifiedFor("target-a", "model") || !manager.IsVerifiedFor("target-b", "model") {
		t.Fatal("target-scoped entries were not independently verified")
	}
	if err := manager.ReleaseModelFor("target-a", "model"); err != nil || len(manager.Snapshot()) != 1 {
		t.Fatalf("target-scoped cleanup removed the wrong entries: err=%v snapshot=%v", err, manager.Snapshot())
	}
	if _, err := manager.ReverifyModel("target-b", "model", path, fingerprint, true); err != nil {
		t.Fatalf("reverification of an existing live pin failed: %v", err)
	}
}

func TestWarmRAMLastUsedPersistsDeterministicLRUVictim(t *testing.T) {
	old := time.Now().UTC().Add(-2 * time.Hour)
	newer := old.Add(time.Hour)
	manager := NewWarmRAMManager(WarmRAMPolicy{MaxWarmBytes: 10})
	manager.entries[warmEntryKey("target", "old")] = &WarmRAMEntry{WarmRAMResult: WarmRAMResult{Model: "old", CanonicalPath: "/models/old", FileFingerprint: "old", Bytes: 5, Verified: true, VRAMReleased: true}, lastUsed: old, pin: &testWarmPin{}, identity: warmFileIdentity{Size: 5, Hash: "old"}, key: warmEntryKey("target", "old"), runtimeFingerprint: "runtime", runtimeEndpoint: "endpoint", runtimeVersion: "version", runtimeProfile: "profile"}
	manager.entries[warmEntryKey("target", "new")] = &WarmRAMEntry{WarmRAMResult: WarmRAMResult{Model: "new", CanonicalPath: "/models/new", FileFingerprint: "new", Bytes: 5, Verified: true, VRAMReleased: true}, lastUsed: newer, pin: &testWarmPin{}, identity: warmFileIdentity{Size: 5, Hash: "new"}, key: warmEntryKey("target", "new"), runtimeFingerprint: "runtime", runtimeEndpoint: "endpoint", runtimeVersion: "version", runtimeProfile: "profile"}
	manager.mu.Lock()
	manager.evictLRULocked(5)
	manager.mu.Unlock()
	if _, exists := manager.entries[warmEntryKey("target", "old")]; exists {
		t.Fatal("oldest entry was not selected as LRU victim")
	}

	restoredSource := NewWarmRAMManager(WarmRAMPolicy{MaxWarmBytes: 10, OpenIdentity: func(path string, _ []string) (warmFileIdentity, error) {
		if strings.HasSuffix(path, "/old") {
			return warmFileIdentity{Size: 5, Hash: "old"}, nil
		}
		return warmFileIdentity{Size: 5, Hash: "new"}, nil
	}})
	restoredSource.entries[warmEntryKey("target", "old")] = &WarmRAMEntry{WarmRAMResult: WarmRAMResult{Model: "old", CanonicalPath: "/models/old", FileFingerprint: "old", Bytes: 5, Verified: true, VRAMReleased: true}, lastUsed: old, identity: warmFileIdentity{Size: 5, Hash: "old"}, key: warmEntryKey("target", "old"), runtimeFingerprint: "runtime", runtimeEndpoint: "endpoint", runtimeVersion: "version", runtimeProfile: "profile"}
	restoredSource.entries[warmEntryKey("target", "new")] = &WarmRAMEntry{WarmRAMResult: WarmRAMResult{Model: "new", CanonicalPath: "/models/new", FileFingerprint: "new", Bytes: 5, Verified: true, VRAMReleased: true}, lastUsed: newer, identity: warmFileIdentity{Size: 5, Hash: "new"}, key: warmEntryKey("target", "new"), runtimeFingerprint: "runtime", runtimeEndpoint: "endpoint", runtimeVersion: "version", runtimeProfile: "profile"}
	manifests := restoredSource.ManifestSnapshot()
	restored := NewWarmRAMManager(WarmRAMPolicy{MaxWarmBytes: 10})
	restored.RestoreManifests(manifests)
	// Restore is metadata-only; emulate the two entries after successful
	// runtime reconciliation so eviction compares their persisted recency.
	for _, key := range []string{warmEntryKey("target", "old"), warmEntryKey("target", "new")} {
		restored.entries[key].pin = &testWarmPin{}
	}
	restored.mu.Lock()
	restored.evictLRULocked(5)
	restored.mu.Unlock()
	if _, exists := restored.entries[warmEntryKey("target", "old")]; exists {
		t.Fatal("restored oldest entry was not selected as LRU victim")
	}
}

func TestWarmRAMInjectedBackendVerifiesIdentityAndCleanup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin := &testWarmPin{resident: 5, locked: 5, closeErr: errors.New("sentinel path cleanup")}
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			return warmFileIdentity{Size: 5}, nil
		},
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return pin, warmFileIdentity{Size: 5}, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 90, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
	})
	if !manager.Supported() {
		t.Fatal("injected warm backend was not recognized")
	}
	result, err := manager.OffloadModel(context.Background(), WarmRAMRequest{Model: "model", Path: path, ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }})
	if err != nil || !result.Verified {
		t.Fatalf("injected backend was not accepted: %+v %v", result, err)
	}
	if err := manager.ReleaseModel("model"); err == nil || len(manager.Snapshot()) != 1 || manager.Snapshot()[0].Verified {
		t.Fatalf("failed cleanup was not retained as unverified: err=%v snapshot=%v", err, manager.Snapshot())
	}
}

func TestWarmRAMIdentityDriftCloseFailureRetainsCleanupHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("a", 64)
	identity := warmFileIdentity{Dev: 1, Ino: 2, Size: 5, Mtime: 3, Hash: fingerprint}
	drift := identity
	drift.Ino = 9
	identityCalls := 0
	pin := &testWarmPin{resident: 5, locked: 5, closeErr: errors.New("close sentinel")}
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			identityCalls++
			if identityCalls > 1 {
				return drift, nil
			}
			return identity, nil
		},
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			return pin, identity, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
	})
	_, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "target", Model: "model", Path: path, ExpectedFingerprint: fingerprint,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }})
	if err == nil || !strings.Contains(err.Error(), "cleanup required") {
		t.Fatalf("identity drift did not surface retained cleanup: %v", err)
	}
	rows := manager.Snapshot()
	if len(rows) != 1 || rows[0].Verified || rows[0].VRAMReleased || pin.closed == false {
		t.Fatalf("identity drift cleanup state was not retained: rows=%+v closed=%t", rows, pin.closed)
	}
	// The only handle remains usable for an explicit signed cleanup retry.
	pin.closeErr = nil
	if err := manager.ReleaseModelFor("target", "model"); err != nil {
		t.Fatalf("cleanup retry failed: %v", err)
	}
	if manager.HasEntryFor("target", "model") {
		t.Fatal("cleanup retry left a stale unverified claim")
	}
}

func TestWarmRAMReverifyIdentityDriftCloseFailureRetainsCleanupHandle(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "model.bin")
	if err := os.WriteFile(path, []byte("model"), 0o600); err != nil {
		t.Fatal(err)
	}
	fingerprint := strings.Repeat("b", 64)
	identity := warmFileIdentity{Dev: 1, Ino: 2, Size: 5, Mtime: 3, Hash: fingerprint}
	drift := identity
	drift.Ino = 10
	identityCalls := 0
	oldPin := &testWarmPin{resident: 5, locked: 5}
	newPin := &testWarmPin{resident: 5, locked: 5, closeErr: errors.New("reverify close sentinel")}
	manager := NewWarmRAMManager(WarmRAMPolicy{
		AllowedRoots: []string{root}, RAMHardCapBytes: 100, RAMReserveBytes: 1, MaxWarmBytes: 100,
		MemlockLimitBytes: 100, PressureRefusalPercent: 90,
		OpenIdentity: func(string, []string) (warmFileIdentity, error) {
			identityCalls++
			if identityCalls == 4 {
				return drift, nil
			}
			return identity, nil
		},
		PinFile: func(string, []string, warmFileIdentity) (warmRAMPin, warmFileIdentity, error) {
			if identityCalls >= 3 {
				return newPin, identity, nil
			}
			return oldPin, identity, nil
		},
		Snapshot:     func() (int64, int64, int64, int64, float64, error) { return 1, 99, 0, 0, 0, nil },
		MemlockLimit: func() (int64, error) { return 100, nil }, Oracle: func() string { return "mincore+mlock" },
	})
	if _, err := manager.OffloadModel(context.Background(), WarmRAMRequest{TargetID: "target", Model: "model", Path: path, ExpectedFingerprint: fingerprint,
		ReleaseVRAM: func(context.Context) error { return nil }, ConfirmReleased: func(context.Context) (bool, error) { return true, nil }}); err != nil {
		t.Fatalf("initial warm failed: %v", err)
	}
	if _, err := manager.ReverifyModel("target", "model", path, fingerprint, true); err == nil || !strings.Contains(err.Error(), "cleanup required") {
		t.Fatalf("reverify identity drift did not retain close failure: %v", err)
	}
	rows := manager.Snapshot()
	if len(rows) != 1 || rows[0].Verified || rows[0].VRAMReleased || !newPin.closed {
		t.Fatalf("reverify did not retain unverified handle: rows=%+v closed=%t", rows, newPin.closed)
	}
	newPin.closeErr = nil
	if err := manager.ReleaseModelFor("target", "model"); err != nil {
		t.Fatalf("reverify cleanup retry failed: %v", err)
	}
}
