package nodeagent

import "testing"

func TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit(t *testing.T) {
	valid := checkpointOwnedStopLifetimeObservation{
		ExitType: "cgroup", ActiveState: "inactive", SubState: "dead", MainPID: 41, ExpectedWorkerPID: 41,
		ExpectedWorkerTicks: 102, SupervisorPID: 40, ExpectedSupervisorTicks: 99, SupervisorInUnit: true,
		SupervisorAlive: true, WorkerExited: true, DurableAckObserved: true, UnitInactiveAfterAck: true,
		ControlGroup: "/system.slice/vram-owned-stop-lifetime-fixture.service",
	}
	if err := validateCheckpointOwnedStopLifetime(valid); err != nil {
		t.Fatalf("complete local lifetime evidence rejected: %v", err)
	}
	mutants := map[string]func(*checkpointOwnedStopLifetimeObservation){
		"wrong ExitType":                     func(o *checkpointOwnedStopLifetimeObservation) { o.ExitType = "main" },
		"wrong MainPID":                      func(o *checkpointOwnedStopLifetimeObservation) { o.MainPID++ },
		"wrong worker incarnation":           func(o *checkpointOwnedStopLifetimeObservation) { o.ExpectedWorkerTicks = 0 },
		"wrong supervisor incarnation":       func(o *checkpointOwnedStopLifetimeObservation) { o.ExpectedSupervisorTicks = 0 },
		"early supervisor death":             func(o *checkpointOwnedStopLifetimeObservation) { o.SupervisorAlive = false },
		"supervisor escaped unit":            func(o *checkpointOwnedStopLifetimeObservation) { o.SupervisorInUnit = false },
		"worker did not exit":                func(o *checkpointOwnedStopLifetimeObservation) { o.WorkerExited = false },
		"missing durable acknowledgement":    func(o *checkpointOwnedStopLifetimeObservation) { o.DurableAckObserved = false },
		"unit exited before acknowledgement": func(o *checkpointOwnedStopLifetimeObservation) { o.UnitInactiveAfterAck = false },
		"unit remained active":               func(o *checkpointOwnedStopLifetimeObservation) { o.ActiveState = "active" },
		"invalid cgroup":                     func(o *checkpointOwnedStopLifetimeObservation) { o.ControlGroup = "/user.slice/../system.slice" },
	}
	for name, mutate := range mutants {
		t.Run(name, func(t *testing.T) {
			bad := valid
			mutate(&bad)
			if err := validateCheckpointOwnedStopLifetime(bad); err == nil {
				t.Fatal("faulted lifetime observation was accepted")
			}
		})
	}
}
