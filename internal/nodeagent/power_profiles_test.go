package nodeagent

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vram-governor/internal/wsproto"
)

func TestSignedGPUPerformanceProfileUsesOnlyFixedLocalCommands(t *testing.T) {
	secret := "0123456789abcdef0123456789abcdef"
	cfg := &Config{NodeID: "node-1", CommandSigningSecret: secret, CommandStatePath: t.TempDir() + "/commands.json"}
	cfg.GPUPerformance.Accelerators = []GPUPerformanceConfig{{Index: 0, IdleCommand: []string{"/usr/bin/nvidia-smi", "-i", "0", "-lgc", "300,450"}, ActiveCommand: []string{"/usr/bin/nvidia-smi", "-i", "0", "-rgc"}}}
	processor := newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var executed [][]string
	processor.runProfileCommand = func(_ context.Context, command []string) error {
		executed = append(executed, append([]string(nil), command...))
		return nil
	}
	command := func(id, profile string) wsproto.CommandPayload {
		row := wsproto.CommandPayload{ID: id, IdempotencyKey: id, NodeID: cfg.NodeID, Command: "set_gpu_performance_profile", Args: map[string]any{"accelerator_id": "node-1-gpu0", "profile": profile, "fencing_token": int64(len(executed) + 1)}, IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute)}
		row.Signature, _ = wsproto.SignCommand(row, []byte(secret))
		return row
	}
	if result := processor.Handle(context.Background(), command("idle", "idle")); !result.OK || result.Result["managed"] != true {
		t.Fatalf("idle command failed: %+v", result)
	}
	if result := processor.Handle(context.Background(), command("active", "active")); !result.OK || result.Result["managed"] != true {
		t.Fatalf("active command failed: %+v", result)
	}
	if !reflect.DeepEqual(executed, [][]string{cfg.GPUPerformance.Accelerators[0].IdleCommand, cfg.GPUPerformance.Accelerators[0].ActiveCommand}) {
		t.Fatalf("executed commands differ from local allowlist: %v", executed)
	}
	foreign := command("foreign", "idle")
	foreign.Args["accelerator_id"] = "node-2-gpu0"
	foreign.Signature, _ = wsproto.SignCommand(foreign, []byte(secret))
	if result := processor.Handle(context.Background(), foreign); result.OK {
		t.Fatalf("foreign accelerator accepted: %+v", result)
	}
	if len(executed) != 2 {
		t.Fatalf("foreign command reached actuator: %v", executed)
	}
}

func TestGPUPerformanceConfigRejectsIncompleteOrDuplicateActuators(t *testing.T) {
	base := "controller_url: ws://127.0.0.1:8080/ws/node\ntoken: dev\nnode_id: node\n"
	for _, body := range []string{
		"gpu_performance:\n  accelerators:\n    - index: 0\n      idle_command: [/usr/bin/nvidia-smi, --reset-gpu-clocks]\n",
		"gpu_performance:\n  accelerators:\n    - index: 0\n      idle_command: [/usr/bin/true]\n      active_command: [/usr/bin/true]\n    - index: 0\n      idle_command: [/usr/bin/true]\n      active_command: [/usr/bin/true]\n",
		"gpu_performance:\n  accelerators:\n    - index: 0\n      idle_command: [nvidia-smi]\n      active_command: [/usr/bin/true]\n",
	} {
		path := filepath.Join(t.TempDir(), "node.yaml")
		if err := os.WriteFile(path, []byte(base+body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatalf("unsafe GPU performance configuration accepted: %s", body)
		}
	}
}
