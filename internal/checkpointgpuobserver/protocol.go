// Package checkpointgpuobserver defines the bounded, signed local protocol
// shared by the root-owned host observer and the unprivileged node adapter.
package checkpointgpuobserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

const (
	ObserverSocketPath = "/run/vram-governor/checkpoint-gpu-observer.sock"
	ProtocolVersion    = 1
	MaxRequestBytes    = 16 << 10
	MaxResponseBytes   = 64 << 10
	MaxNSpidDepth      = 32
	MaxCgroupBytes     = 4096
	MaxUnixPeerRoles   = 8
	MaxGPUProcessRows  = 4096
)

var (
	bootIDPattern  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	gpuUUIDPattern = regexp.MustCompile(`^GPU-[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)
	pciPattern     = regexp.MustCompile(`^(?:[0-9A-Fa-f]{4}|[0-9A-Fa-f]{8}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$`)
)

// Request contains only facts sampled by the node adapter from its local
// process and namespace descriptors. The server treats every field as an
// untrusted selector and independently proves the host-side joins.
type Request struct {
	Version              int    `json:"version"`
	Nonce                string `json:"nonce"`
	InitPID              int    `json:"init_pid"`
	InitStartTicks       uint64 `json:"init_start_ticks"`
	InitNamespaceDev     uint64 `json:"init_namespace_dev"`
	InitNamespaceInode   uint64 `json:"init_namespace_inode"`
	InitNamespaceFS      uint64 `json:"init_namespace_fs"`
	InitNamespaceType    uint64 `json:"init_namespace_type"`
	WorkerPID            int    `json:"worker_pid"`
	WorkerStartTicks     uint64 `json:"worker_start_ticks"`
	WorkerNamespaceDev   uint64 `json:"worker_namespace_dev"`
	WorkerNamespaceInode uint64 `json:"worker_namespace_inode"`
	WorkerNamespaceFS    uint64 `json:"worker_namespace_fs"`
	WorkerNamespaceType  uint64 `json:"worker_namespace_type"`
	GPUUUID              string `json:"gpu_uuid"`
	GPUPCI               string `json:"gpu_pci"`
}

// Namespace records the held descriptor identity, filesystem type, and
// namespace kind observed by the host. Device and inode are both required.
type Namespace struct {
	Device        uint64 `json:"device"`
	Inode         uint64 `json:"inode"`
	Filesystem    uint64 `json:"filesystem"`
	NamespaceType uint64 `json:"namespace_type"`
}

// Process records a process incarnation and its host-visible namespace and
// cgroup membership. NSpid is the complete host-to-current-namespace chain.
type Process struct {
	PID        int       `json:"pid"`
	StartTicks uint64    `json:"start_ticks"`
	NSpid      []int     `json:"nspid"`
	Namespace  Namespace `json:"namespace"`
	Cgroup     string    `json:"cgroup"`
}

// GPUProcess is the single measured process row joined to the worker PID.
type GPUProcess struct {
	PID   int    `json:"pid"`
	UUID  string `json:"uuid"`
	Bytes int64  `json:"bytes"`
}

// Response binds the exact request to fresh host, caller, namespace, cgroup,
// device, and process-footprint observations. ExpiresAtUnixNS is short-lived.
type Response struct {
	Version              int        `json:"version"`
	RequestSHA256        string     `json:"request_sha256"`
	Nonce                string     `json:"nonce"`
	BootID               string     `json:"boot_id"`
	Role                 string     `json:"role"`
	PeerUID              uint32     `json:"peer_uid"`
	PeerExecutablePath   string     `json:"peer_executable_path"`
	PeerExecutableSHA256 string     `json:"peer_executable_sha256"`
	Peer                 Process    `json:"peer"`
	Init                 Process    `json:"init"`
	Worker               Process    `json:"worker"`
	GPU                  GPUProcess `json:"gpu"`
	GPUUUID              string     `json:"gpu_uuid"`
	GPUPCI               string     `json:"gpu_pci"`
	ObservedAtUnixNS     int64      `json:"observed_at_unix_ns"`
	ExpiresAtUnixNS      int64      `json:"expires_at_unix_ns"`
}

// Envelope is a canonical base64 wrapper around a canonical signed response.
type Envelope struct {
	Version   int    `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

const responseDomain = "vram-governor/checkpoint-gpu-observer/v1\x00"

// MarshalRequest validates and returns the only accepted request encoding.
func MarshalRequest(request Request) ([]byte, error) {
	if err := ValidateRequest(request); err != nil {
		return nil, err
	}
	b, err := json.Marshal(request)
	if err != nil || len(b) == 0 || len(b) > MaxRequestBytes {
		return nil, errors.New("observer request exceeds protocol bounds")
	}
	return b, nil
}

// DecodeRequest rejects noncanonical encodings, duplicate keys, nulls, and
// unknown fields before the observer considers the request.
func DecodeRequest(raw []byte) (Request, error) {
	var request Request
	if len(raw) == 0 || len(raw) > MaxRequestBytes || rejectDuplicateKeys(raw) != nil {
		return request, errors.New("observer request is empty, oversized, or malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, errors.New("observer request fields are invalid")
	}
	if err := requireEOF(decoder); err != nil {
		return Request{}, errors.New("observer request contains trailing data")
	}
	canonical, err := MarshalRequest(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Request{}, errors.New("observer request is not canonical")
	}
	return request, nil
}

func ValidateRequest(request Request) error {
	if request.Version != ProtocolVersion || !isLowerHex(request.Nonce, 64) ||
		request.InitPID != 1 || request.InitStartTicks == 0 || request.InitNamespaceDev == 0 || request.InitNamespaceInode == 0 || request.InitNamespaceFS == 0 || request.InitNamespaceType == 0 ||
		request.WorkerPID <= 1 || request.WorkerStartTicks == 0 || request.WorkerNamespaceDev == 0 || request.WorkerNamespaceInode == 0 || request.WorkerNamespaceFS == 0 || request.WorkerNamespaceType == 0 ||
		request.InitNamespaceDev != request.WorkerNamespaceDev || request.InitNamespaceInode != request.WorkerNamespaceInode ||
		request.InitNamespaceFS != request.WorkerNamespaceFS || request.InitNamespaceType != request.WorkerNamespaceType ||
		!gpuUUIDPattern.MatchString(request.GPUUUID) || !pciPattern.MatchString(request.GPUPCI) {
		return errors.New("observer request identity is incomplete or outside bounds")
	}
	return nil
}

func SignResponse(response Response, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("observer signing key is invalid")
	}
	if err := ValidateResponse(response); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(response)
	if err != nil || len(payload) == 0 || len(payload) > MaxResponseBytes-(2<<10) {
		return nil, errors.New("observer response exceeds protocol bounds")
	}
	signed := append([]byte(responseDomain), payload...)
	signature := ed25519.Sign(privateKey, signed)
	envelope := Envelope{Version: ProtocolVersion, Payload: base64.RawStdEncoding.EncodeToString(payload), Signature: base64.RawStdEncoding.EncodeToString(signature)}
	encoded, err := json.Marshal(envelope)
	if err != nil || len(encoded) == 0 || len(encoded) > MaxResponseBytes {
		return nil, errors.New("observer response envelope exceeds protocol bounds")
	}
	return encoded, nil
}

func VerifyResponse(raw []byte, publicKey ed25519.PublicKey, expected Request, nowUnixNS int64) (Response, error) {
	var envelope Envelope
	if len(raw) == 0 || len(raw) > MaxResponseBytes || len(publicKey) != ed25519.PublicKeySize || rejectDuplicateKeys(raw) != nil {
		return Response{}, errors.New("observer response envelope is empty, oversized, or malformed")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || requireEOF(decoder) != nil || envelope.Version != ProtocolVersion {
		return Response{}, errors.New("observer response envelope fields are invalid")
	}
	canonicalEnvelope, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(raw, canonicalEnvelope) {
		return Response{}, errors.New("observer response envelope is not canonical")
	}
	payload, err := base64.RawStdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxResponseBytes-(2<<10) || base64.RawStdEncoding.EncodeToString(payload) != envelope.Payload {
		return Response{}, errors.New("observer response payload encoding is invalid")
	}
	signature, err := base64.RawStdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != envelope.Signature {
		return Response{}, errors.New("observer response signature encoding is invalid")
	}
	signed := append([]byte(responseDomain), payload...)
	if !ed25519.Verify(publicKey, signed, signature) {
		return Response{}, errors.New("observer response signature is invalid")
	}
	var response Response
	if rejectDuplicateKeys(payload) != nil {
		return Response{}, errors.New("observer signed payload contains duplicate fields")
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || requireEOF(decoder) != nil {
		return Response{}, errors.New("observer signed payload is malformed")
	}
	canonicalPayload, err := json.Marshal(response)
	if err != nil || !bytes.Equal(payload, canonicalPayload) {
		return Response{}, errors.New("observer signed payload is not canonical")
	}
	if err := ValidateResponse(response); err != nil {
		return Response{}, err
	}
	requestBytes, err := MarshalRequest(expected)
	if err != nil {
		return Response{}, err
	}
	requestDigest := sha256.Sum256(requestBytes)
	if response.Nonce != expected.Nonce || response.RequestSHA256 != hex.EncodeToString(requestDigest[:]) ||
		response.GPUUUID != expected.GPUUUID || !strings.EqualFold(response.GPUPCI, expected.GPUPCI) ||
		response.Worker.NSpid[len(response.Worker.NSpid)-1] != expected.WorkerPID ||
		response.Init.NSpid[len(response.Init.NSpid)-1] != expected.InitPID ||
		response.Init.StartTicks != expected.InitStartTicks || response.Worker.StartTicks != expected.WorkerStartTicks ||
		response.Init.Namespace.Device != expected.InitNamespaceDev || response.Init.Namespace.Inode != expected.InitNamespaceInode ||
		response.Init.Namespace.Filesystem != expected.InitNamespaceFS || response.Init.Namespace.NamespaceType != expected.InitNamespaceType ||
		response.Worker.Namespace.Device != expected.WorkerNamespaceDev || response.Worker.Namespace.Inode != expected.WorkerNamespaceInode ||
		response.Worker.Namespace.Filesystem != expected.WorkerNamespaceFS || response.Worker.Namespace.NamespaceType != expected.WorkerNamespaceType {
		return Response{}, errors.New("observer response does not bind the exact local request")
	}
	if nowUnixNS <= 0 || response.ObservedAtUnixNS > nowUnixNS || response.ExpiresAtUnixNS <= nowUnixNS || response.ExpiresAtUnixNS-response.ObservedAtUnixNS > int64(5e9) {
		return Response{}, errors.New("observer response is stale, future-dated, or outside the short TTL")
	}
	return response, nil
}

func ValidateResponse(response Response) error {
	if response.Version != ProtocolVersion || !isLowerHex(response.RequestSHA256, 64) || !isLowerHex(response.Nonce, 64) ||
		!bootIDPattern.MatchString(response.BootID) || response.Role != "node-agent" && response.Role != "fixed-supervisor" && response.Role != "local-observer" ||
		!filepathIsAbsoluteCanonical(response.PeerExecutablePath) || !isLowerHex(response.PeerExecutableSHA256, 64) ||
		response.ObservedAtUnixNS <= 0 || response.ExpiresAtUnixNS <= response.ObservedAtUnixNS || response.ExpiresAtUnixNS-response.ObservedAtUnixNS > int64(5e9) ||
		!validProcess(response.Peer) || !validProcess(response.Init) || !validProcess(response.Worker) ||
		response.GPU.PID != response.Worker.PID || response.GPU.Bytes <= 0 || !gpuUUIDPattern.MatchString(response.GPU.UUID) ||
		response.GPU.UUID != response.GPUUUID || !gpuUUIDPattern.MatchString(response.GPUUUID) || !pciPattern.MatchString(response.GPUPCI) {
		return errors.New("observer response identity or measurement is invalid")
	}
	if response.Init.NSpid[len(response.Init.NSpid)-1] != 1 || response.Worker.Namespace != response.Init.Namespace || response.Peer.Namespace != response.Init.Namespace ||
		response.Worker.Cgroup == "" || response.Init.Cgroup == "" || response.Peer.Cgroup == "" ||
		response.Role == "node-agent" && response.PeerUID == 0 || (response.Role == "fixed-supervisor" || response.Role == "local-observer") && response.PeerUID != 0 {
		return errors.New("observer response process joins are incomplete")
	}
	return nil
}

func filepathIsAbsoluteCanonical(value string) bool {
	return value != "" && strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && !strings.Contains(value, "//") && !strings.Contains(value, "/../") && !strings.HasSuffix(value, "/..") && !strings.ContainsRune(value, '\x00')
}

func validProcess(process Process) bool {
	if process.PID <= 1 || process.StartTicks == 0 || len(process.NSpid) == 0 || len(process.NSpid) > MaxNSpidDepth || process.NSpid[0] != process.PID ||
		process.Namespace.Device == 0 || process.Namespace.Inode == 0 || process.Namespace.Filesystem == 0 || process.Namespace.NamespaceType == 0 ||
		len(process.Cgroup) == 0 || len(process.Cgroup) > MaxCgroupBytes || strings.ContainsRune(process.Cgroup, '\x00') || !strings.HasPrefix(process.Cgroup, "/") {
		return false
	}
	for index, pid := range process.NSpid {
		if pid <= 0 || (pid == 1 && index != len(process.NSpid)-1) {
			return false
		}
	}
	return true
}

func isLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			if token == nil {
				return errors.New("null is not accepted")
			}
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate or invalid JSON key")
				}
				seen[name] = true
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unterminated object")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unterminated array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	return requireEOF(decoder)
}
