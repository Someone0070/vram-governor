package api

import (
	"context"
	"testing"

	"vram-governor/internal/wsproto"
)

func TestAMDTelemetryPreservesVendorAndMemoryKind(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	ctx := context.Background()
	if _, err := srv.registerNode(ctx, wsproto.RegisterPayload{NodeID: "amd-node", NodeName: "AMD node", LocationClass: "local", PowerControlMode: "dont_touch"}); err != nil {
		t.Fatal(err)
	}
	srv.handleTelemetry(ctx, "amd-node", wsproto.TelemetryPayload{NodeID: "amd-node", Accelerators: []wsproto.AcceleratorTelemetry{{Index: 0, Vendor: "amd", Name: "AMD Phoenix3", MemoryKind: "unified", VRAMTotalMB: 16384, VRAMUsedMB: 8192, VRAMFreeMB: 8192}}})
	node, err := srv.nodes.GetNode(ctx, "amd-node")
	if err != nil {
		t.Fatal(err)
	}
	if len(node.Accelerators) != 1 || node.Accelerators[0].Vendor != "amd" || node.Accelerators[0].MemoryKind != "unified" || node.Accelerators[0].ID != "amd-node-gpu0" {
		t.Fatalf("AMD telemetry was misclassified: %+v", node.Accelerators)
	}
	srv.handleTelemetry(ctx, "amd-node", wsproto.TelemetryPayload{NodeID: "amd-node", Accelerators: []wsproto.AcceleratorTelemetry{{Index: 0, Name: "old NVIDIA agent", VRAMTotalMB: 10240}}})
	node, err = srv.nodes.GetNode(ctx, "amd-node")
	if err != nil {
		t.Fatal(err)
	}
	if node.Accelerators[0].Vendor != "nvidia" {
		t.Fatal("old node agent lost backward-compatible NVIDIA vendor")
	}
}
