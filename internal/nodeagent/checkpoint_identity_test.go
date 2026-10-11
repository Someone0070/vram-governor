package nodeagent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func TestCheckpointLocalIdentityRequestValidation(t *testing.T) {
	modelHash := stringsOf('a', 64)
	exeHash := stringsOf('b', 64)
	good := CheckpointIdentityRequest{
		Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit,
		ModelPath: "/models/demo.gguf", ExpectedModelSHA256: modelHash,
		ApprovedModelRoots: []string{"/models"}, ExpectedExecutableSHA256: exeHash,
	}
	t.Run("accepts bounded literal loopback request", func(t *testing.T) {
		canonical, ip, port, err := parseCheckpointIdentityEndpoint(good.Endpoint)
		if err != nil || canonical != good.Endpoint || ip.String() != "127.0.0.1" || port != 8080 {
			t.Fatalf("valid endpoint rejected: canonical=%q ip=%v port=%d err=%v", canonical, ip, port, err)
		}
	})
	if canonical, ip, port, err := parseCheckpointIdentityEndpoint("http://[::1]:8080"); err != nil || canonical != "http://[::1]:8080" || ip.String() != "::1" || port != 8080 {
		t.Fatalf("valid IPv6 loopback endpoint rejected: canonical=%q ip=%v port=%d err=%v", canonical, ip, port, err)
	}
	for name, endpoint := range map[string]string{
		"remote host": "http://example.com:8080", "DNS localhost": "http://localhost:8080",
		"wildcard": "http://0.0.0.0:8080", "https": "https://127.0.0.1:8080",
		"credentials": "http://user:secret@127.0.0.1:8080", "path": "http://127.0.0.1:8080/v1",
		"missing port": "http://127.0.0.1", "zero port": "http://127.0.0.1:0",
		"query": "http://127.0.0.1:8080/?model=x", "fragment": "http://127.0.0.1:8080/#x",
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			if _, _, _, err := parseCheckpointIdentityEndpoint(endpoint); err == nil {
				t.Fatalf("accepted unsafe endpoint %q", endpoint)
			}
		})
	}
	for name, mutate := range map[string]func(*CheckpointIdentityRequest){
		"unlisted unit":          func(r *CheckpointIdentityRequest) { r.ServiceUnit = "other.service" },
		"missing model pin":      func(r *CheckpointIdentityRequest) { r.ExpectedModelSHA256 = "" },
		"missing executable pin": func(r *CheckpointIdentityRequest) { r.ExpectedExecutableSHA256 = "unknown" },
		"missing roots":          func(r *CheckpointIdentityRequest) { r.ApprovedModelRoots = nil },
		"relative model path":    func(r *CheckpointIdentityRequest) { r.ModelPath = "model.gguf" },
		"model path traversal":   func(r *CheckpointIdentityRequest) { r.ModelPath = "/models/../secret.gguf" },
		"root path traversal":    func(r *CheckpointIdentityRequest) { r.ApprovedModelRoots = []string{"/models/../outside"} },
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			req := good
			mutate(&req)
			if _, err := ObserveCheckpointLocalIdentity(context.Background(), req); err == nil {
				t.Fatal("invalid identity request was accepted")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveCheckpointLocalIdentity(ctx, good); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observation context was not honored: %v", err)
	}
	if _, err := ObserveCheckpointLocalIdentity(nil, good); err == nil {
		t.Fatal("nil context was accepted")
	}
}

func TestCheckpointLocalIdentityFingerprintBindsProcessAndArtifact(t *testing.T) {
	base := CheckpointLocalIdentity{
		Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit,
		BootID: "00000000-0000-0000-0000-000000000001", PID: 42, ProcessStartTicks: 123,
		ListenerIP: "127.0.0.1", ListenerPort: 8080, ListenerSocketInode: 1234,
		ExecutablePath: "/usr/bin/llama-server", ExecutableDevice: 5, ExecutableInode: 6, ExecutableSize: 7,
		ExecutableSHA256: stringsOf('a', 64), ModelPath: "/models/a.gguf", ModelSHA256: stringsOf('b', 64),
		ModelDevice: 1, ModelInode: 2, ModelSize: 3,
	}
	first := checkpointIdentityFingerprint(base)
	if len(first) != sha256.Size*2 || first != checkpointIdentityFingerprint(base) {
		t.Fatalf("fingerprint is malformed or unstable: %q", first)
	}
	changed := base
	changed.ProcessStartTicks++
	if first == checkpointIdentityFingerprint(changed) {
		t.Fatal("fingerprint did not bind process incarnation")
	}
	changed = base
	changed.ModelInode++
	if first == checkpointIdentityFingerprint(changed) {
		t.Fatal("fingerprint did not bind observed model file identity")
	}
	changed = base
	changed.ListenerSocketInode++
	if first == checkpointIdentityFingerprint(changed) {
		t.Fatal("fingerprint did not bind listener socket identity")
	}
	changed = base
	changed.ExecutableInode++
	if first == checkpointIdentityFingerprint(changed) {
		t.Fatal("fingerprint did not bind executable file identity")
	}
	if _, err := hex.DecodeString(first); err != nil {
		t.Fatalf("fingerprint is not hex: %v", err)
	}
}

func TestCheckpointLocalIdentityClockStepsNeverVerifyLoadProvenance(t *testing.T) {
	identity := CheckpointLocalIdentity{ObservedMappedBytes: 4096, ModelSHA256: stringsOf('a', 64)}
	wallClock := time.Unix(1_700_000_000, 0)
	for _, step := range []time.Duration{-365 * 24 * time.Hour, 2 * 365 * 24 * time.Hour} {
		wallClock = wallClock.Add(step)
		_ = wallClock // wall time is deliberately not an input to provenance.
		if identity.HasVerifiedLoadProvenance() || identity.LoadProvenance() != CheckpointLoadProvenanceUnknown {
			t.Fatal("a wall-clock step promoted current file/mapping observations to historical load provenance")
		}
	}
}

func stringsOf(ch byte, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = ch
	}
	return string(b)
}
