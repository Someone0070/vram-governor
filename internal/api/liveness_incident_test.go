package api

import (
	"context"
	"testing"
	"time"

	"vram-governor/internal/domain"
	"vram-governor/internal/store"
	"vram-governor/internal/wsproto"
)

func TestLivenessObserverCreatesOneNodeLossIncidentAndVerifiesRecovery(t *testing.T) {
	srv, _, cancel := testServer(t)
	defer cancel()
	backing, ok := srv.nodes.(*store.MemoryStore)
	if !ok {
		t.Fatalf("unexpected node store %T", srv.nodes)
	}
	ctx := context.Background()
	_, err := backing.UpsertNode(ctx, &domain.Node{
		ID: "gpu-node", Name: "test GPU node",
		SchedulingState: domain.SchedulingDraining,
		Desired:         domain.Desired{SchedulingEnabled: false, Power: domain.DesiredPowerOn},
		Observed:        domain.Observed{Connectivity: domain.ConnectivityConnected, Ready: true, LastHeartbeat: time.Now().Add(-time.Minute)},
	})
	if err != nil {
		t.Fatal(err)
	}

	srv.sweepLiveness(ctx, 2*time.Second, 5*time.Second)
	srv.sweepLiveness(ctx, 2*time.Second, 5*time.Second)
	incidents, err := backing.ListIncidents(ctx, "system")
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Status != "open" || incidents[0].Severity != "S2" || len(incidents[0].EvidenceRefs) != 1 || incidents[0].EvidenceRefs[0] != "node:gpu-node" {
		t.Fatalf("unexpected node-loss incidents: %+v", incidents)
	}
	node, _ := backing.GetNode(ctx, "gpu-node")
	if node.Observed.Connectivity != domain.ConnectivityLost || node.Observed.Ready {
		t.Fatalf("node was not marked lost: %+v", node.Observed)
	}

	reconnected := srv.registerNode(ctx, wsproto.RegisterPayload{NodeID: "gpu-node", NodeName: "test GPU node", LocationClass: "local", PowerControlMode: "manual"})
	if reconnected.Observed.Connectivity != domain.ConnectivityConnected || reconnected.SchedulingState != domain.SchedulingDraining || reconnected.Desired.SchedulingEnabled {
		t.Fatalf("reconnect erased durable node intent: %+v", reconnected)
	}
	incidents, err = backing.ListIncidents(ctx, "system")
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].Status != "recovered" {
		t.Fatalf("node recovery was not verified: %+v", incidents)
	}
	events, err := backing.ListAuditEvents(ctx, "system", 10)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, event := range events {
		seen[event.Type] = true
	}
	if !seen["incident.node_lost"] || !seen["incident.node_recovered"] {
		t.Fatalf("node lifecycle audit events missing: %+v", seen)
	}
}
