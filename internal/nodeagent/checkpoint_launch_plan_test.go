package nodeagent

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
)

func TestCheckpointLaunchPlanBoundsAndArguments(t *testing.T) {
	p := CheckpointLaunchPlan{Alias: "safe-model", Model: CheckpointLaunchModel{Path: "/model", SHA256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Bytes: 1024}, Executable: CheckpointLaunchExecutable{Path: "/server", SHA256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}, Endpoint: CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080}, TotalContextTokens: 4096, ParallelSlots: 4, SnapshotRoot: "/snapshots", Custody: CheckpointLaunchCustodyQuotas{Root: "/custody", MaxArtifactBytes: 1024, MaxStagingBytes: 2048, ReserveBytes: 1024}}
	args := fixedCheckpointLaunchArguments(p)
	if len(args) != 15 {
		t.Fatalf("fixed argument count=%d, want 15: %#v", len(args), args)
	}
	if args[0] != "-m" || args[1] != "{CHECKPOINT_MODEL}" || args[2] != "--alias" || args[3] != p.Alias || args[4] != "--host" || args[5] != net.ParseIP(p.Endpoint.Host).String() || args[6] != "--port" || args[7] != "8080" || args[8] != "--no-webui" || args[9] != "-c" || args[10] != "4096" || args[11] != "--parallel" || args[12] != "4" || args[13] != "--slot-save-path" {
		t.Fatalf("unexpected fixed arguments: %#v", args)
	}
	if args[len(args)-1] != "/snapshots" {
		t.Fatalf("snapshot directory missing: %#v", args)
	}
	count := 0
	for _, arg := range args {
		if arg == "{CHECKPOINT_MODEL}" {
			count++
		}
		if arg == "" {
			t.Fatal("empty fixed argument")
		}
	}
	if count != 1 {
		t.Fatalf("placeholder count=%d, want one", count)
	}
}

func TestCheckpointLaunchPlanPathSyntaxRejectsTraversalAndControls(t *testing.T) {
	for _, path := range []string{"", "relative/file", "/safe/../unsafe", "/safe/./file", "/safe/with\nnewline", "/safe/with\x00nul", "/safe/with\x01control", "/safe/with\x7fdelete"} {
		if err := validateCanonicalPathSyntax(path); err == nil {
			t.Errorf("accepted unsafe path %q", path)
		}
	}
}

func TestCheckpointLaunchPlanRuntimeOptionsSchema(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("plan parsing checks Unix execute bits; the fixed launcher runs only on Linux")
	}
	base := checkpointRuntimeOptionsPlanJSON(t, checkpointLaunchPlanVersion2, nil)
	if _, err := ParseCheckpointLaunchPlan(base); err != nil {
		t.Fatalf("v2 plan without optional runtime_options rejected: %v", err)
	}
	options := &CheckpointLaunchRuntimeOptions{KVUnified: true, FlashAttention: "off", CheckpointDescriptor: true}
	valid := checkpointRuntimeOptionsPlanJSON(t, checkpointLaunchPlanVersion2, options)
	if _, err := ParseCheckpointLaunchPlan(valid); err != nil {
		t.Fatalf("supported runtime_options tuple rejected: %v", err)
	}
	legacy := checkpointRuntimeOptionsPlanJSON(t, checkpointLaunchPlanVersion, nil)
	if _, err := ParseCheckpointLaunchPlan(legacy); err != nil {
		t.Fatalf("v1 plan without runtime_options rejected: %v", err)
	}

	missingKV := strings.Replace(string(valid), `"kv_unified":true,`, "", 1)
	missingFlash := strings.Replace(string(valid), `"flash_attention":"off",`, "", 1)
	missingDescriptor := strings.Replace(string(valid), `,"checkpoint_descriptor":true`, "", 1)
	duplicateRoot := strings.Replace(string(valid), `"runtime_options":`, `"runtime_options":`+string(checkpointRuntimeOptionsJSON(t, options))+`,"runtime_options":`, 1)
	duplicateNested := strings.Replace(string(valid), `"kv_unified":true`, `"kv_unified":true,"kv_unified":true`, 1)
	caseAlias := strings.Replace(string(valid), `"flash_attention":`, `"Flash_Attention":`, 1)
	unknown := strings.Replace(string(valid), `"checkpoint_descriptor":true`, `"checkpoint_descriptor":true,"future":false`, 1)
	badOptions := []struct {
		name string
		raw  string
	}{
		{"v1 presence", string(checkpointRuntimeOptionsPlanJSON(t, checkpointLaunchPlanVersion, options))},
		{"explicit null", strings.Replace(string(base), `"placement":`, `"runtime_options":null,"placement":`, 1)},
		{"missing kv_unified", missingKV},
		{"missing flash_attention", missingFlash},
		{"missing checkpoint_descriptor", missingDescriptor},
		{"unknown nested key", unknown},
		{"case aliased nested key", caseAlias},
		{"duplicate root key", duplicateRoot},
		{"duplicate nested key", duplicateNested},
		{"kv_unified false", strings.Replace(string(valid), `"kv_unified":true`, `"kv_unified":false`, 1)},
		{"flash attention on", strings.Replace(string(valid), `"flash_attention":"off"`, `"flash_attention":"on"`, 1)},
		{"descriptor false", strings.Replace(string(valid), `"checkpoint_descriptor":true`, `"checkpoint_descriptor":false`, 1)},
	}
	for _, tc := range badOptions {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseCheckpointLaunchPlan([]byte(tc.raw)); err == nil {
				t.Fatalf("invalid runtime_options accepted: %s", tc.name)
			}
		})
	}
}

func checkpointRuntimeOptionsPlanJSON(t *testing.T, version string, options *CheckpointLaunchRuntimeOptions) []byte {
	t.Helper()
	dir := t.TempDir()
	modelPath := filepath.Join(dir, "model.gguf")
	executablePath := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(modelPath, []byte("model"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executablePath, []byte("executable"), 0700); err != nil {
		t.Fatal(err)
	}
	plan := CheckpointLaunchPlan{
		Version: version, Alias: "runtime-options-test",
		Model:              CheckpointLaunchModel{Path: modelPath, SHA256: strings.Repeat("a", 64), Bytes: 5},
		Executable:         CheckpointLaunchExecutable{Path: executablePath, SHA256: strings.Repeat("b", 64)},
		Endpoint:           CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080},
		TotalContextTokens: 1024, ParallelSlots: 1,
		SnapshotRoot:   filepath.Join(dir, "snapshots"),
		Custody:        CheckpointLaunchCustodyQuotas{Root: filepath.Join(dir, "custody"), MaxArtifactBytes: 1024, MaxStagingBytes: 2048, ReserveBytes: 0},
		RuntimeOptions: options,
	}
	if err := os.Mkdir(plan.SnapshotRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(plan.Custody.Root, 0700); err != nil {
		t.Fatal(err)
	}
	if version == checkpointLaunchPlanVersion2 {
		plan.Placement = &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "0.3.0-dev (build 1, commit 62acc89)", MaxAccelerators: 1, OffloadPolicy: "full_gpu", MinGPUBytes: 1, MaxHostRSSBytes: 1 << 30}
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func checkpointRuntimeOptionsJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
