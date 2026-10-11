package nodeagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCheckpointLocalObserverCanonicalRequest(t *testing.T) {
	nonce := strings.Repeat("a", checkpointLocalObserverNonceBytes*2)
	canonical, err := checkpointLocalObserverCanonicalRequest(nonce)
	if err != nil {
		t.Fatal(err)
	}
	request, err := checkpointLocalObserverDecodeRequest(canonical)
	if err != nil || request.Version != checkpointLocalObserverVersion || request.Nonce != nonce {
		t.Fatalf("known canonical request rejected: %#v, %v", request, err)
	}
	for name, raw := range map[string]string{
		"duplicate":       `{"version":1,"version":1,"nonce":"` + nonce + `"}`,
		"unknown":         `{"version":1,"nonce":"` + nonce + `","pid":1}`,
		"case-variant":    `{"Version":1,"nonce":"` + nonce + `"}`,
		"null":            `{"version":1,"nonce":null}`,
		"whitespace":      `{"version":1, "nonce":"` + nonce + `"}`,
		"trailing-value":  string(canonical) + ` {}`,
		"short-nonce":     `{"version":1,"nonce":"a"}`,
		"unsupported-ver": `{"version":2,"nonce":"` + nonce + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := checkpointLocalObserverDecodeRequest([]byte(raw)); err == nil {
				t.Fatalf("malformed %s request was accepted", name)
			}
		})
	}
}

func TestCheckpointLocalObserverSignedResponseBoundaries(t *testing.T) {
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := checkpointLocalObserverTestPayload(time.Now().UTC())
	wire, err := checkpointLocalObserverSign(payload, private)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointLocalObserverVerify(wire, pub, payload.Nonce, time.Now().UTC()); err != nil {
		t.Fatalf("known positive signature rejected: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checkpointLocalObserverVerify(wire, otherPub, payload.Nonce, time.Now().UTC()); err == nil {
		t.Fatal("wrong pinned root key was accepted")
	}
	if _, err := checkpointLocalObserverVerify(wire, pub, strings.Repeat("b", 64), time.Now().UTC()); err == nil {
		t.Fatal("replayed response nonce was accepted")
	}
	if _, err := checkpointLocalObserverVerify(wire, pub, payload.Nonce, time.Now().Add(11*time.Second)); err == nil {
		t.Fatal("expired response was accepted")
	}
	var envelope checkpointLocalObserverEnvelope
	if err := json.Unmarshal(wire, &envelope); err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(envelope.Signature)
	sig[0] ^= 1
	envelope.Signature = hex.EncodeToString(sig)
	forged, _ := json.Marshal(envelope)
	if _, err := checkpointLocalObserverVerify(forged, pub, payload.Nonce, time.Now().UTC()); err == nil {
		t.Fatal("forged signature was accepted")
	}
	if _, err := checkpointLocalObserverVerify(append([]byte(" "), wire...), pub, payload.Nonce, time.Now().UTC()); err == nil {
		t.Fatal("noncanonical signed envelope was accepted")
	}
}

func TestCheckpointLocalObserverIdentityAndBindingJoins(t *testing.T) {
	payload := checkpointLocalObserverTestPayload(time.Now().UTC())
	if err := checkpointLocalObserverValidatePayload(payload, time.Now().UTC(), false); err != nil {
		t.Fatalf("known joined payload rejected: %v", err)
	}
	checks := map[string]func(*checkpointLocalObserverPayload){
		"caller-pid-namespace": func(p *checkpointLocalObserverPayload) { p.Caller.PIDNamespaceInode++ },
		"worker-executable":    func(p *checkpointLocalObserverPayload) { p.Worker.ExecutableSHA256 = strings.Repeat("f", 64) },
		"worker-start":         func(p *checkpointLocalObserverPayload) { p.Worker.StartTicks++ },
		"custody-digest":       func(p *checkpointLocalObserverPayload) { p.Binding.CustodyBindingSHA256 = strings.Repeat("f", 64) },
		"init-pid":             func(p *checkpointLocalObserverPayload) { p.Init.PID = 2 },
		"init-not-root":        func(p *checkpointLocalObserverPayload) { p.Init.UID = 65534 },
		"worker-not-root":      func(p *checkpointLocalObserverPayload) { p.Worker.UID = 65534 },
		"pid-1-worker":         func(p *checkpointLocalObserverPayload) { p.Worker.PID = 1 },
		"expired": func(p *checkpointLocalObserverPayload) {
			p.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
		},
	}
	for name, mutate := range checks {
		t.Run(name, func(t *testing.T) {
			p := checkpointLocalObserverTestPayload(time.Now().UTC())
			mutate(&p)
			if err := checkpointLocalObserverValidatePayload(p, time.Now().UTC(), false); err == nil {
				t.Fatalf("mutated %s payload passed", name)
			}
		})
	}
}

func checkpointLocalObserverTestPayload(now time.Time) checkpointLocalObserverPayload {
	boot := "00000000-0000-0000-0000-000000000001"
	ns := uint64(4026532000)
	caller := CheckpointLocalObserverIdentity{PID: 100, UID: 65534, GID: 65534, StartTicks: 101, PIDNamespaceInode: ns, ExecutablePath: "/usr/local/bin/node-agent", ExecutableSHA256: strings.Repeat("1", 64), ControlGroup: "/system.slice/vram-governor-node-agent.service", BootID: boot}
	init := CheckpointLocalObserverIdentity{PID: 1, UID: 0, GID: 0, StartTicks: 1, PIDNamespaceInode: ns, ExecutablePath: "/sbin/init", ExecutableSHA256: strings.Repeat("2", 64), ControlGroup: "/init.scope", BootID: boot}
	worker := CheckpointLocalObserverIdentity{PID: 200, UID: 0, GID: 0, StartTicks: 202, PIDNamespaceInode: ns, ExecutablePath: "/var/lib/vram-governor/checkpoint-custody/launchers/server", ExecutableSHA256: strings.Repeat("3", 64), ControlGroup: "/system.slice/llama-server.service", BootID: boot}
	localIdentity := CheckpointLocalIdentity{EvidenceKind: "controlled-source-fs-verity-v2", Endpoint: "http://127.0.0.1:8080", ServiceUnit: checkpointIdentityServiceUnit, BootID: boot, PID: worker.PID, ProcessStartTicks: worker.StartTicks, ListenerIP: "127.0.0.1", ListenerPort: 8080, ListenerSocketInode: 909, ExecutablePath: worker.ExecutablePath, ExecutableSHA256: worker.ExecutableSHA256}
	custody := CheckpointCustodyVerification{EvidenceKind: "controlled-source-fs-verity-v2", ModelArgument: "/proc/self/fd/4", ArgvSHA256: strings.Repeat("4", 64), BindingSHA256: strings.Repeat("5", 64), Nonce: strings.Repeat("6", 64), Endpoint: localIdentity.Endpoint, ServiceUnit: checkpointIdentityServiceUnit, UnitAssociation: "label-only-unverified", BootID: boot, PID: worker.PID, ProcessStartTicks: worker.StartTicks, ListenerSocketInode: localIdentity.ListenerSocketInode, ActualAlias: "fixed-alias"}
	association := CheckpointVerifiedUnitAssociation{Custody: custody, Identity: localIdentity, Invocation: "00000000000000000000000000000000", ControlGroup: worker.ControlGroup}
	return checkpointLocalObserverPayload{Version: checkpointLocalObserverVersion, Nonce: strings.Repeat("a", 64), IssuedAt: now.UTC().Format(time.RFC3339Nano), ExpiresAt: now.Add(checkpointLocalObserverMaxLifetime).UTC().Format(time.RFC3339Nano), Caller: caller, Init: init, Worker: worker, Binding: CheckpointManagedBinding{Version: checkpointLaunchPlanVersion2, CurrentIncarnation: strings.Repeat("7", 64), PlanSHA256: strings.Repeat("8", 64), CustodyBindingSHA256: custody.BindingSHA256, Alias: "fixed-alias", Association: association, Placement: CheckpointDevicePlacement{Backend: "cuda", PhysicalIdentity: "GPU-01234567-89ab-cdef-0123-456789abcdef", ChildMaskUUID: "GPU-01234567-89ab-cdef-0123-456789abcdef", RuntimeDeviceToken: "CUDA0", RuntimeVersion: "0.3.0"}, GPUBytes: 1, HostRSSBytes: 1, ObservedAt: now.UTC().Format(time.RFC3339Nano)}}
}
