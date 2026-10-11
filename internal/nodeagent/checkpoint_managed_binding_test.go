package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"strings"
	"testing"
)

const managedModelPositive = `{"object":"list","data":[{"id":"resident-a","aliases":["resident-a"],"tags":["managed"],"object":"model","created":1730000000,"owned_by":"llamacpp","meta":{"vocab_type":2,"n_vocab":32000,"n_ctx":4096,"n_ctx_train":8192,"n_embd":4096,"n_params":7000000000,"size":4200000000,"ftype":"Q4_K_M"}}]}`

func TestCheckpointManagedBindingControls(t *testing.T) {
	changed := func(mutated string) string {
		t.Helper()
		if mutated == managedModelPositive {
			t.Fatal("parser negative-control fixture did not change from the valid positive")
		}
		return mutated
	}
	replace := func(old, replacement string) string {
		t.Helper()
		if !strings.Contains(managedModelPositive, old) {
			t.Fatalf("parser negative-control fixture anchor is absent: %q", old)
		}
		mutated := strings.Replace(managedModelPositive, old, replacement, 1)
		return changed(mutated)
	}
	entryStart := strings.Index(managedModelPositive, `"data":[`) + len(`"data":[`)
	entryEnd := strings.LastIndex(managedModelPositive, `]}`)
	if entryStart < len(`"data":[`) || entryEnd <= entryStart {
		t.Fatal("positive parser fixture is malformed for duplicate-entry control")
	}
	entry := managedModelPositive[entryStart:entryEnd]
	ambiguousModels := changed(managedModelPositive[:entryEnd] + "," + entry + managedModelPositive[entryEnd:])
	noModels := changed(managedModelPositive[:entryStart] + managedModelPositive[entryEnd:])
	truncated := changed(managedModelPositive[:len(managedModelPositive)-1])
	trailing := changed(managedModelPositive + `{}`)
	oversized := changed(string(bytes.Repeat([]byte(managedModelPositive), checkpointManagedHTTPMax/len(managedModelPositive)+1)))
	for _, test := range []struct {
		name string
		raw  string
	}{
		{name: "one_exact_alias", raw: managedModelPositive},
		{name: "duplicate_alias_field", raw: replace(`"id":"resident-a"`, `"id":"resident-a","id":"resident-a"`)},
		{name: "case_alias", raw: replace(`"id":"resident-a"`, `"Id":"resident-a"`)},
		{name: "ambiguous_model_list", raw: ambiguousModels},
		{name: "wrong_model_object", raw: replace(`"object":"model"`, `"object":"collection"`)},
		{name: "no_loaded_model", raw: noModels},
		{name: "truncated_response", raw: truncated},
		{name: "unexpected_metadata", raw: replace(`"ftype":"Q4_K_M"`, `"ftype":"Q4_K_M","extra":true`)},
		{name: "trailing_data", raw: trailing},
		{name: "alias_id_disagrees", raw: replace(`"id":"resident-a"`, `"id":"other"`)},
		{name: "ambiguous_aliases", raw: replace(`["resident-a"]`, `["resident-a","other"]`)},
		{name: "duplicate_alias_value", raw: replace(`["resident-a"]`, `["resident-a","resident-a"]`)},
		{name: "null_aliases", raw: replace(`["resident-a"]`, `null`)},
		{name: "null_alias_member", raw: replace(`["resident-a"]`, `[null]`)},
		{name: "null_tags", raw: replace(`["managed"]`, `null`)},
		{name: "null_tag_member", raw: replace(`["managed"]`, `[null]`)},
		{name: "empty_tag_member", raw: replace(`["managed"]`, `[""]`)},
		{name: "null_string_id", raw: replace(`"id":"resident-a"`, `"id":null`)},
		{name: "created_string", raw: replace(`1730000000`, `"1730000000"`)},
		{name: "metadata_fraction", raw: replace(`"n_ctx":4096`, `"n_ctx":4096.5`)},
		{name: "metadata_null", raw: replace(`"vocab_type":2`, `"vocab_type":null`)},
		{name: "ftype_null", raw: replace(`"ftype":"Q4_K_M"`, `"ftype":null`)},
		{name: "metadata_case_alias", raw: replace(`"n_vocab":32000`, `"N_vocab":32000`)},
		{name: "wrong_owner", raw: replace(`"owned_by":"llamacpp"`, `"owned_by":"other"`)},
		{name: "ftype_numeric_instead_of_string", raw: replace(`"ftype":"Q4_K_M"`, `"ftype":15`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			alias, err := parseManagedCheckpointModelList([]byte(test.raw), "resident-a")
			if test.name == "one_exact_alias" {
				if err != nil || alias != "resident-a" {
					t.Fatalf("pinned llama.cpp schema was rejected: alias=%q error=%v", alias, err)
				}
				return
			}
			if err == nil {
				t.Fatal("malformed, unknown, or ambiguous model response was accepted")
			}
		})
	}
	t.Run("oversized_response", func(t *testing.T) {
		if _, err := parseManagedCheckpointModelList([]byte(oversized), "resident-a"); err == nil {
			t.Fatal("oversized model response was accepted")
		}
	})
}

func TestCheckpointManagedBindingFaultControls(t *testing.T) {
	argv := []string{"/approved/llama-server", "-m", "/proc/self/fd/4", "--alias", "resident-a", "--host", "127.0.0.1", "--port", "8080", "--no-webui", "-c", "4096", "--parallel", "2", "--slot-save-path", "/snapshots", "--device", "CUDA0", "--split-mode", "none", "--main-gpu", "0", "--n-gpu-layers", "all"}
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{name: "positive_exact_argv", mutate: func(args []string) []string { return args }},
		{name: "missing_argv0", mutate: func(args []string) []string { return args[1:] }},
		{name: "context_substitution", mutate: func(args []string) []string { args[11] = "8192"; return args }},
		{name: "slot_substitution", mutate: func(args []string) []string { args[13] = "3"; return args }},
		{name: "model_operand_confusion", mutate: func(args []string) []string { args[2] = "/approved/model.gguf"; return args }},
		{name: "descriptor_confusion", mutate: func(args []string) []string { args[2] = "/proc/self/fd/5"; return args }},
		{name: "staged_executable_argv0", mutate: func(args []string) []string { args[0] = "/var/lib/custody/launchers/server"; return args }},
		{name: "extra_argv", mutate: func(args []string) []string { return append(args, "--extra-option") }},
		{name: "snapshot_root_substitution", mutate: func(args []string) []string { args[15] = "/other/snapshots"; return args }},
		{name: "placement_flag_substitution", mutate: func(args []string) []string { args[21] = "1"; return args }},
		{name: "empty_argument", mutate: func(args []string) []string { args[2] = ""; return args }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := test.mutate(append([]string(nil), argv...))
			accepted := equalCheckpointArgv(got, argv)
			if test.name == "positive_exact_argv" {
				if !accepted {
					t.Fatal("exact reconstructed child argv was rejected")
				}
				return
			}
			if accepted {
				t.Fatal("mutated fixed child argv was accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("worker\x00-m"), []byte("worker\x00\x00"), bytes.Repeat([]byte{'x'}, (16<<10)+1)} {
		if _, err := parseManagedCheckpointArgv(raw); err == nil {
			t.Fatal("malformed, truncated, or oversized live argv was accepted")
		}
	}
	if _, err := managedCheckpointExpectedArgv(CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion}); err == nil {
		t.Fatal("legacy plan produced managed argv")
	}
}

func TestCheckpointManagedBindingFreshnessControls(t *testing.T) {
	association := CheckpointVerifiedUnitAssociation{
		Invocation: "0123456789abcdef0123456789abcdef", ControlGroup: "/system.slice/llama-server.service",
		Custody:  CheckpointCustodyVerification{BindingSHA256: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 64), ArgvSHA256: strings.Repeat("c", 64), VerityDigest: strings.Repeat("d", 64), PrelaunchBootNS: 1, StartBootNS: 2, StartedBootNS: 3},
		Identity: CheckpointLocalIdentity{EvidenceKind: "controlled-source-fs-verity-v2", Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit, BootID: "00000000-0000-0000-0000-000000000001", PID: 1400, ProcessStartTicks: 77, ListenerIP: "127.0.0.1", ListenerPort: 8080, ListenerSocketInode: 91, ExecutablePath: "/staged/exe", ExecutableSHA256: "exe", ExecutableDevice: 8, ExecutableInode: 20, ExecutableSize: 1024, ModelPath: "/staged/models/model.gguf", ModelSHA256: "model", ModelDevice: 8, ModelInode: 21, ModelSize: 4096, ObservedMappedBytes: 100, Fingerprint: "measurement-is-not-incarnation"},
	}
	plan := CheckpointLaunchPlan{Alias: "resident-a", Model: CheckpointLaunchModel{Path: "/approved/model.gguf", SHA256: "model"}, Executable: CheckpointLaunchExecutable{Path: "/approved/llama-server", SHA256: "exe"}, Placement: &CheckpointLaunchPlacement{Backend: "cuda", IdentityKind: "uuid", PhysicalIdentity: "GPU-00000000-0000-0000-0000-000000000001", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "llama.cpp commit 62acc89", MaxAccelerators: 1}}
	argv := []string{"/approved/llama-server", "/proc/self/fd/4", "-c", "4096", "--parallel", "2", "--slot-save-path", "/snapshots", "--device", "CUDA0"}
	first := managedCheckpointCurrentIncarnation(association, plan, argv)
	if len(first) != 64 {
		t.Fatalf("current incarnation digest length = %d", len(first))
	}
	changedObservation := association
	changedObservation.Identity.ObservedMappedBytes = 999
	changedObservation.Identity.Fingerprint = "different-measured-fingerprint"
	changedObservation.Custody.PrelaunchBootNS = 900
	changedObservation.Custody.StartBootNS = 901
	changedObservation.Custody.StartedBootNS = 902
	second := managedCheckpointCurrentIncarnation(changedObservation, plan, argv)
	if first != second {
		t.Fatal("timestamps or changing measured mapping facts altered current incarnation")
	}
	changedProcess := association
	changedProcess.Identity.PID++
	if managedCheckpointCurrentIncarnation(changedProcess, plan, argv) == first {
		t.Fatal("PID substitution did not change current incarnation")
	}
	changedArgv := append([]string(nil), argv...)
	changedArgv[3] = "8192"
	if managedCheckpointCurrentIncarnation(association, plan, changedArgv) == first {
		t.Fatal("context launch setting substitution did not change current incarnation")
	}
	changedPlan := plan
	changedPlan.Model.Path += ".replaced"
	if managedCheckpointCurrentIncarnation(association, changedPlan, argv) == first {
		t.Fatal("model path replacement under identical hashes and context/slots did not change current incarnation")
	}
	digest := sha256.Sum256([]byte(first))
	if hex.EncodeToString(digest[:]) == first {
		t.Fatal("current incarnation is not a digest of association material")
	}
}

func TestCheckpointManagedBindingUnsupportedPlatform(t *testing.T) {
	if runtime.GOOS == "linux" {
		return
	}
	if _, err := ObserveCheckpointManagedLocalBinding(context.Background()); err == nil {
		t.Fatal("unsupported platform produced a managed binding")
	}
}
