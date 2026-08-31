package nodeagent

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"vram-governor/internal/wsproto"
)

func TestTelemetrySamplingPreservesLastInventoryAfterDriverFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int32
	query := func(context.Context) ([]wsproto.AcceleratorTelemetry, error) {
		if calls.Add(1) == 1 {
			return []wsproto.AcceleratorTelemetry{{Index: 0, Name: "gpu0", VRAMTotalMB: 10240, VRAMUsedMB: 2048}}, nil
		}
		return nil, errors.New("driver temporarily busy")
	}
	out := make(chan wsproto.TelemetryPayload, 1)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	go telemetrySamplingLoop(ctx, &Config{NodeID: "node-a", HeartbeatIntervalSeconds: 1}, log, &SystemSampler{}, nil, query, out)

	first := <-out
	if len(first.Accelerators) != 1 || first.Accelerators[0].VRAMUsedMB != 2048 {
		t.Fatalf("unexpected initial inventory: %+v", first.Accelerators)
	}
	select {
	case second := <-out:
		if len(second.Accelerators) != 1 || second.Accelerators[0].Name != "gpu0" {
			t.Fatalf("last good inventory was discarded: %+v", second.Accelerators)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("telemetry loop did not publish after a transient driver failure")
	}
}
