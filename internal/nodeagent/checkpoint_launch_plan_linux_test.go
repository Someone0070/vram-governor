//go:build linux

package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type launchPlanFixture struct {
	dir, planPath string
	raw           []byte
	plan          CheckpointLaunchPlan
}

func newLaunchPlanFixture(t *testing.T) launchPlanFixture {
	t.Helper()
	root, err := os.MkdirTemp("/run", ".checkpoint-launch-plan-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	model := filepath.Join(root, "model.gguf")
	if err = os.WriteFile(model, []byte("small fixture weights"), 0600); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, "llama-server")
	if err = os.WriteFile(exe, []byte("fixture executable"), 0700); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(root, "snapshots")
	custody := filepath.Join(root, "custody")
	for _, p := range []string{snap, custody} {
		if err = os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	plan := CheckpointLaunchPlan{Version: checkpointLaunchPlanVersion, Alias: "model-x", Model: CheckpointLaunchModel{Path: model, SHA256: strings.Repeat("a", 64), Bytes: 21}, Executable: CheckpointLaunchExecutable{Path: exe, SHA256: strings.Repeat("b", 64)}, Endpoint: CheckpointLaunchEndpoint{Host: "127.0.0.1", Port: 8080}, TotalContextTokens: 4096, ParallelSlots: 4, SnapshotRoot: snap, Custody: CheckpointLaunchCustodyQuotas{Root: custody, MaxArtifactBytes: 1024, MaxStagingBytes: 2048, ReserveBytes: 512}}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "plan.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return launchPlanFixture{dir: root, planPath: path, raw: raw, plan: plan}
}

func TestCheckpointLaunchPlanStrictParsing(t *testing.T) {
	f := newLaunchPlanFixture(t)
	got, err := ParseCheckpointLaunchPlan(f.raw)
	if err != nil {
		t.Fatal(err)
	}
	if got != f.plan {
		t.Fatalf("parsed plan mismatch: %#v", got)
	}
	duplicate := append([]byte(nil), f.raw...)
	duplicate = append(duplicate[:len(duplicate)-1], []byte(`,"alias":"second"}`)...)
	modelPathJSON, _ := json.Marshal(f.plan.Model.Path)
	nestedDuplicate := strings.Replace(string(f.raw), `"path":`+string(modelPathJSON), `"path":`+string(modelPathJSON)+`,"path":`+string(modelPathJSON), 1)
	unknown := strings.Replace(string(f.raw), `"alias":`, `"unknown":1,"alias":`, 1)
	nestedUnknown := strings.Replace(string(f.raw), `"sha256":`, `"unexpected":1,"sha256":`, 1)
	casefoldAlias := strings.Replace(string(f.raw), `"alias":"model-x"`, `"alias":"model-x","Alias":"evil"`, 1)
	nestedCasefoldPath := strings.Replace(string(f.raw), `"path":`+string(modelPathJSON), `"path":`+string(modelPathJSON)+`,"Path":`+string(modelPathJSON), 1)
	missingReserve := strings.Replace(string(f.raw), `,"reserve_bytes":512`, ``, 1)
	nullReserve := strings.Replace(string(f.raw), `"reserve_bytes":512`, `"reserve_bytes":null`, 1)
	nullHost := strings.Replace(string(f.raw), `"host":"127.0.0.1"`, `"host":null`, 1)
	invalidUTF8 := append([]byte(nil), f.raw...)
	aliasOffset := bytes.Index(invalidUTF8, []byte("model-x"))
	if aliasOffset < 0 {
		t.Fatal("fixture alias absent")
	}
	invalidUTF8[aliasOffset] = 0xff
	for name, candidate := range map[string]string{"nested duplicate": nestedDuplicate, "nested unknown": nestedUnknown, "casefold alias": casefoldAlias, "nested casefold": nestedCasefoldPath, "missing reserve": missingReserve, "null reserve": nullReserve, "null host": nullHost} {
		if candidate == string(f.raw) {
			t.Fatalf("%s negative fixture did not change the JSON", name)
		}
	}
	trailing := append(append([]byte(nil), f.raw...), []byte(` {}`)...)
	oversized := append(append([]byte(nil), f.raw...), []byte(strings.Repeat(" ", checkpointLaunchPlanMaxBytes+1-len(f.raw)))...)
	slotInt64Max := strings.Replace(string(f.raw), `"parallel_slots":4`, `"parallel_slots":9223372036854775807`, 1)
	slotOverInt64 := strings.Replace(string(f.raw), `"parallel_slots":4`, `"parallel_slots":9223372036854775808`, 1)
	for name, raw := range map[string][]byte{"duplicate": duplicate, "nested duplicate": []byte(nestedDuplicate), "unknown": []byte(unknown), "nested unknown": []byte(nestedUnknown), "casefold alias": []byte(casefoldAlias), "casefold nested path": []byte(nestedCasefoldPath), "missing reserve field": []byte(missingReserve), "null reserve field": []byte(nullReserve), "null host": []byte(nullHost), "invalid UTF-8": invalidUTF8, "trailing": trailing, "oversized": oversized, "noninteger": []byte(strings.Replace(string(f.raw), `"port":8080`, `"port":8.5`, 1)), "wrong type": []byte(strings.Replace(string(f.raw), `"parallel_slots":4`, `"parallel_slots":"4"`, 1)), "slots int64 max": []byte(slotInt64Max), "slots over int64": []byte(slotOverInt64)} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCheckpointLaunchPlan(raw); err == nil {
				t.Fatalf("accepted %s plan", name)
			}
		})
	}
}

func TestCheckpointLaunchPlanInvalidJSON(t *testing.T) {
	f := newLaunchPlanFixture(t)
	invalid := []struct {
		name   string
		mutate func(*CheckpointLaunchPlan)
	}{
		{"alias", func(p *CheckpointLaunchPlan) { p.Alias = "bad alias" }},
		{"sha", func(p *CheckpointLaunchPlan) { p.Model.SHA256 = "abc" }},
		{"endpoint", func(p *CheckpointLaunchPlan) { p.Endpoint.Host = "localhost" }},
		{"endpoint URL", func(p *CheckpointLaunchPlan) { p.Endpoint.Host = "http://127.0.0.1" }},
		{"context low", func(p *CheckpointLaunchPlan) { p.TotalContextTokens = 255 }},
		{"context slot mismatch", func(p *CheckpointLaunchPlan) { p.TotalContextTokens = 1023; p.ParallelSlots = 4 }},
		{"slot overflow bound", func(p *CheckpointLaunchPlan) { p.TotalContextTokens = 1048577 }},
		{"slots high", func(p *CheckpointLaunchPlan) { p.ParallelSlots = 129 }},
		{"artifact quota low", func(p *CheckpointLaunchPlan) { p.Custody.MaxArtifactBytes = p.Model.Bytes - 1 }},
		{"artifact quota high", func(p *CheckpointLaunchPlan) { p.Custody.MaxArtifactBytes = custodyMaxArtifactBytes + 1 }},
		{"staging quota high", func(p *CheckpointLaunchPlan) { p.Custody.MaxStagingBytes = custodyMaxStagingBytes + 1 }},
		{"staging model plus reserve", func(p *CheckpointLaunchPlan) { p.Custody.MaxStagingBytes = p.Model.Bytes + p.Custody.ReserveBytes - 1 }},
		{"reserve quota", func(p *CheckpointLaunchPlan) {
			p.Custody.MaxStagingBytes = custodyMaxStagingBytes
			p.Custody.ReserveBytes = checkpointCustodyMaxReserveForTest + 1
		}},
		{"path traversal", func(p *CheckpointLaunchPlan) {
			p.SnapshotRoot = f.dir + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "outside"
		}},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			p := f.plan
			test.mutate(&p)
			raw, _ := json.Marshal(p)
			if _, err := ParseCheckpointLaunchPlan(raw); err == nil {
				t.Fatalf("accepted invalid %s field", test.name)
			}
		})
	}
	for name, linkPath := range map[string]string{"model symlink": filepath.Join(f.dir, "model-link.gguf"), "executable symlink": filepath.Join(f.dir, "server-link")} {
		target := f.plan.Model.Path
		if name == "executable symlink" {
			target = f.plan.Executable.Path
		}
		if err := os.Symlink(target, linkPath); err != nil {
			t.Fatal(err)
		}
		p := f.plan
		if name == "model symlink" {
			p.Model.Path = linkPath
		} else {
			p.Executable.Path = linkPath
		}
		raw, _ := json.Marshal(p)
		if _, err := ParseCheckpointLaunchPlan(raw); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
}

func TestCheckpointLaunchPlanV2PlacementStrictParsing(t *testing.T) {
	f := newLaunchPlanFixture(t)
	p := f.plan
	p.Version = checkpointLaunchPlanVersion2
	p.Placement = checkpointPlacementFixture().Placement
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCheckpointLaunchPlan(raw)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("valid v2 placement plan rejected: err=%v got=%+v", err, got)
	}
	if err := os.WriteFile(f.planPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	pinned, err := privateOpenCheckpointLaunchPlan(context.Background(), f.planPath, uint32(os.Geteuid()))
	if err != nil {
		t.Fatalf("private v2 plan pin failed: %v", err)
	}
	defer pinned.Close()
	snapshot := pinned.Spec()
	snapshot.Placement.RuntimeDeviceToken = "CUDA9"
	if pinned.Spec().Placement.RuntimeDeviceToken != "CUDA0" {
		t.Fatal("returned v2 placement mutated the pinned plan snapshot")
	}
	for name, candidate := range map[string][]byte{
		"missing placement":          []byte(strings.Replace(string(raw), `,"placement":`+mustJSONForTest(t, p.Placement), "", 1)),
		"duplicate device token":     []byte(strings.Replace(string(raw), `"runtime_device_token":"CUDA0"`, `"runtime_device_token":"CUDA0","runtime_device_token":"CUDA0"`, 1)),
		"casefold physical identity": []byte(strings.Replace(string(raw), `"physical_identity":"GPU-01234567-89ab-cdef-0123-456789abcdef"`, `"physical_identity":"GPU-01234567-89ab-cdef-0123-456789abcdef","Physical_Identity":"GPU-01234567-89ab-cdef-0123-456789abcdef"`, 1)),
		"unexpected placement field": []byte(strings.Replace(string(raw), `"backend":"cuda"`, `"backend":"cuda","vendor_product":"fast"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, parseErr := ParseCheckpointLaunchPlan(candidate); parseErr == nil {
				t.Fatalf("accepted malformed v2 plan: %s", name)
			}
		})
	}
	p.Placement.MaxAccelerators = 2
	raw, _ = json.Marshal(p)
	if _, err := ParseCheckpointLaunchPlan(raw); err == nil {
		t.Fatal("accepted a future multi-accelerator ceiling as current managed support")
	}
}

func mustJSONForTest(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

const checkpointCustodyMaxReserveForTest int64 = 1 << 30

func TestCheckpointLaunchPlanPinnedRecheck(t *testing.T) {
	t.Run("stable", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if err = p.Recheck(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("pathname replacement", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		old := f.planPath + ".old"
		if err = os.Rename(f.planPath, old); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(f.planPath, f.raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err = p.Recheck(context.Background()); err == nil || !strings.Contains(err.Error(), "pathname") {
			t.Fatalf("replacement error=%v, want pathname marker", err)
		}
	})
	t.Run("same inode mutation", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		raw := append([]byte(nil), f.raw...)
		i := strings.Index(string(raw), "model-x")
		if i < 0 {
			t.Fatal("fixture alias absent")
		}
		file, err := os.OpenFile(f.planPath, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.WriteAt([]byte{'y'}, int64(i+len("model-")))
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = p.Recheck(context.Background()); err == nil || !strings.Contains(err.Error(), "bytes changed") {
			t.Fatalf("mutation error=%v, want bytes changed marker", err)
		}
	})
}

func TestCheckpointLaunchPlanDefensiveCopies(t *testing.T) {
	f := newLaunchPlanFixture(t)
	p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	spec := p.Spec()
	spec.Alias = "attacker"
	args := p.Arguments()
	args[1] = "/untrusted/model"
	if p.Spec().Alias != f.plan.Alias || p.Arguments()[1] != "{CHECKPOINT_MODEL}" {
		t.Fatal("returned plan or arguments mutated retained state")
	}
}

func TestCheckpointLaunchPlanCancellationClosedAndPublicUID(t *testing.T) {
	f := newLaunchPlanFixture(t)
	if os.Geteuid() != 0 {
		t.Fatal("public launch-plan policy test requires root fixture execution")
	}
	p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err = p.Recheck(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled recheck error=%v", err)
	}
	if err = p.Close(); err != nil {
		t.Fatal(err)
	}
	if err = p.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if err = p.Recheck(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("closed recheck error=%v", err)
	}
	if err = os.Chown(f.planPath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenCheckpointLaunchPlan(context.Background(), f.planPath); err == nil {
		t.Fatal("public policy accepted a non-root plan file")
	} else if !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("public UID rejection returned unexpected error: %v", err)
	}
	seam, err := privateOpenCheckpointLaunchPlan(context.Background(), f.planPath, 65534)
	if err != nil {
		t.Fatalf("private expected-UID test seam rejected its owner: %v", err)
	}
	defer seam.Close()
	if err := seam.Recheck(context.Background()); err != nil {
		t.Fatalf("private expected-UID recheck failed: %v", err)
	}
}

func TestCheckpointLaunchPlanUnsafeFileAndParents(t *testing.T) {
	t.Run("hard link", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		if err := os.Link(f.planPath, f.planPath+".link"); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath); err == nil || !strings.Contains(err.Error(), "links") {
			t.Fatalf("hard link error=%v", err)
		}
	})
	t.Run("writable plan file", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		if err := os.Chmod(f.planPath, 0620); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath); err == nil {
			t.Fatal("accepted group-writable plan file")
		}
	})
	t.Run("fifo nonblocking", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		fifo := filepath.Join(f.dir, "fifo")
		if err := unix.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCheckpointLaunchPlan(context.Background(), fifo); err == nil {
			t.Fatal("accepted FIFO plan")
		}
	})
	t.Run("symlink", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		link := filepath.Join(f.dir, "plan-link")
		if err := os.Symlink(f.planPath, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenCheckpointLaunchPlan(context.Background(), link); err == nil {
			t.Fatal("accepted symlink plan")
		}
	})
	t.Run("public root directory mode", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		if err := os.Chmod(f.dir, 0777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(f.dir, 0700)
		if _, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath); err == nil || !strings.Contains(err.Error(), "trusted") {
			t.Fatalf("unsafe parent error=%v", err)
		}
	})
	t.Run("parent identity change", func(t *testing.T) {
		f := newLaunchPlanFixture(t)
		p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if err = os.Chmod(f.dir, 0710); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(f.dir, 0700)
		if err = p.Recheck(context.Background()); err == nil || !strings.Contains(err.Error(), "parent identity or mode") {
			t.Fatalf("changed parent error=%v", err)
		}
	})
}

func TestCheckpointLaunchPlanRecheckCanceledContext(t *testing.T) {
	f := newLaunchPlanFixture(t)
	p, err := OpenCheckpointLaunchPlan(context.Background(), f.planPath)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := p.Recheck(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled descriptor recheck error=%v", err)
	}
}
