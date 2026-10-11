package checkpointgpuobserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func protocolFixture(t *testing.T) (Request, Response, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		Version: ProtocolVersion, Nonce: strings.Repeat("a", 64), InitPID: 1, InitStartTicks: 101,
		InitNamespaceDev: 4, InitNamespaceInode: 55, InitNamespaceFS: 0x6e736673, InitNamespaceType: 0x20000000,
		WorkerPID: 37, WorkerStartTicks: 202, WorkerNamespaceDev: 4, WorkerNamespaceInode: 55,
		WorkerNamespaceFS: 0x6e736673, WorkerNamespaceType: 0x20000000,
		GPUUUID: "GPU-00000000-0000-0000-0000-000000000001", GPUPCI: "0000:01:00.0",
	}
	requestBytes, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(requestBytes)
	response := Response{
		Version: ProtocolVersion, RequestSHA256: hex.EncodeToString(digest[:]), Nonce: request.Nonce,
		BootID: "00000000-0000-0000-0000-000000000002", Role: "node-agent",
		PeerUID: 1100, PeerExecutablePath: "/usr/sbin/vram-node-agent", PeerExecutableSHA256: strings.Repeat("c", 64),
		Peer:   Process{PID: 800, StartTicks: 303, NSpid: []int{800, 5}, Namespace: Namespace{4, 55, 0x6e736673, 0x20000000}, Cgroup: "/ct.slice/worker"},
		Init:   Process{PID: 900, StartTicks: request.InitStartTicks, NSpid: []int{900, 1}, Namespace: Namespace{4, 55, 0x6e736673, 0x20000000}, Cgroup: "/ct.slice/init"},
		Worker: Process{PID: 937, StartTicks: request.WorkerStartTicks, NSpid: []int{937, request.WorkerPID}, Namespace: Namespace{4, 55, 0x6e736673, 0x20000000}, Cgroup: "/ct.slice/worker"},
		GPU:    GPUProcess{PID: 937, UUID: request.GPUUUID, Bytes: 1 << 30}, GPUUUID: request.GPUUUID, GPUPCI: request.GPUPCI,
		ObservedAtUnixNS: 10_000_000_000, ExpiresAtUnixNS: 12_000_000_000,
	}
	return request, response, public, private
}

func TestRequestCanonicalValidation(t *testing.T) {
	request, _, _, _ := protocolFixture(t)
	encoded, err := MarshalRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeRequest(encoded); err != nil {
		t.Fatalf("canonical request rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":    []byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1)),
		"case variant": []byte(strings.Replace(string(encoded), `"version"`, `"Version"`, 1)),
		"unknown":      []byte(strings.Replace(string(encoded), `"version":1`, `"version":1,"other":1`, 1)),
		"null":         []byte(strings.Replace(string(encoded), `"nonce":"`+request.Nonce+`"`, `"nonce":null`, 1)),
		"whitespace":   []byte(" " + string(encoded)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(raw); err == nil {
				t.Fatal("malformed request was accepted")
			}
		})
	}
}

func TestSignedResponseBindsNonceAndIncarnations(t *testing.T) {
	request, response, public, private := protocolFixture(t)
	encoded, err := SignResponse(response, private)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyResponse(encoded, public, request, 11_000_000_000)
	if err != nil || verified.GPU.Bytes != response.GPU.Bytes {
		t.Fatalf("valid response rejected: response=%#v err=%v", verified, err)
	}
	wrongKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResponse(encoded, wrongKey, request, 11_000_000_000); err == nil {
		t.Fatal("response signed by an unpinned key was accepted")
	}
	mutated := request
	mutated.WorkerStartTicks++
	if _, err := VerifyResponse(encoded, public, mutated, 11_000_000_000); err == nil {
		t.Fatal("response for a previous worker incarnation was accepted")
	}
	if _, err := VerifyResponse(encoded, public, request, response.ExpiresAtUnixNS); err == nil {
		t.Fatal("expired response was accepted")
	}
	localObserver := response
	localObserver.Role = "local-observer"
	localObserver.PeerUID = 0
	localEncoded, err := SignResponse(localObserver, private)
	if err != nil {
		t.Fatalf("exact root local-observer response rejected: %v", err)
	}
	if verified, err := VerifyResponse(localEncoded, public, request, 11_000_000_000); err != nil || verified.Role != "local-observer" {
		t.Fatalf("exact local-observer role did not verify: role=%q err=%v", verified.Role, err)
	}
	rootSupervisor := response
	rootSupervisor.Role = "fixed-supervisor"
	rootSupervisor.PeerUID = 0
	supervisorEncoded, err := SignResponse(rootSupervisor, private)
	if err != nil {
		t.Fatalf("exact root fixed-supervisor response rejected: %v", err)
	}
	if verified, err := VerifyResponse(supervisorEncoded, public, request, 11_000_000_000); err != nil || verified.Role != "fixed-supervisor" {
		t.Fatalf("root fixed-supervisor role did not verify: role=%q err=%v", verified.Role, err)
	}
	rootSupervisor.PeerUID = 1100
	if _, err := SignResponse(rootSupervisor, private); err == nil {
		t.Fatal("nonroot fixed-supervisor role was accepted")
	}
	unknownRole := response
	unknownRole.Role = "unknown-observer"
	if _, err := SignResponse(unknownRole, private); err == nil {
		t.Fatal("unknown observer role was accepted")
	}
	localObserver.PeerUID = 1100
	if _, err := SignResponse(localObserver, private); err == nil {
		t.Fatal("nonroot local-observer role was accepted")
	}
}

func TestResponseRejectsGPUAndNamespaceSubstitution(t *testing.T) {
	request, response, public, private := protocolFixture(t)
	for name, mutate := range map[string]func(*Response){
		"multiple row identity": func(response *Response) { response.GPU.PID++ },
		"wrong GPU UUID":        func(response *Response) { response.GPUUUID = "GPU-00000000-0000-0000-0000-000000000099" },
		"namespace device":      func(response *Response) { response.Worker.Namespace.Device++ },
		"namespace inode":       func(response *Response) { response.Init.Namespace.Inode++ },
		"namespace type":        func(response *Response) { response.Worker.Namespace.NamespaceType++ },
		"init chain":            func(response *Response) { response.Init.NSpid[len(response.Init.NSpid)-1] = 2 },
		"empty cgroup":          func(response *Response) { response.Worker.Cgroup = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := response
			changed.Peer = response.Peer
			changed.Init = response.Init
			changed.Worker = response.Worker
			changed.Peer.NSpid = append([]int(nil), response.Peer.NSpid...)
			changed.Init.NSpid = append([]int(nil), response.Init.NSpid...)
			changed.Worker.NSpid = append([]int(nil), response.Worker.NSpid...)
			mutate(&changed)
			encoded, err := SignResponse(changed, private)
			if err == nil {
				if _, err = VerifyResponse(encoded, public, request, 11_000_000_000); err == nil {
					t.Fatal("substituted signed response was accepted")
				}
			}
		})
	}
}

func TestRepeatedNumericNSpidAcrossNamespacesIsValid(t *testing.T) {
	request, response, public, private := protocolFixture(t)
	response.Worker.NSpid = []int{937, 37, 37}
	encoded, err := SignResponse(response, private)
	if err != nil {
		t.Fatalf("repeated numeric PID at distinct namespace levels was rejected: %v", err)
	}
	if _, err := VerifyResponse(encoded, public, request, 11_000_000_000); err != nil {
		t.Fatalf("valid namespace PID chain rejected: %v", err)
	}
}

func TestEnvelopeRejectsDuplicateFieldsAndBadEncoding(t *testing.T) {
	request, response, public, private := protocolFixture(t)
	encoded, err := SignResponse(response, private)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(string(encoded), `"version":1`, `"version":1,"version":1`, 1)
	if _, err := VerifyResponse([]byte(duplicate), public, request, 11_000_000_000); err == nil {
		t.Fatal("duplicate envelope key was accepted")
	}
	var envelope map[string]any
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope["payload"] = envelope["payload"].(string) + "="
	badEncoding, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyResponse(badEncoding, public, request, 11_000_000_000); err == nil {
		t.Fatal("noncanonical base64 was accepted")
	}
}
