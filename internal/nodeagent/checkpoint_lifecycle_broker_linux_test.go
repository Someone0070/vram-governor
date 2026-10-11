//go:build linux

package nodeagent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"vram-governor/internal/wsproto"
)

type planBrokerColdDirInfoFixture struct {
	ownedStopKeyInfoFixture
}

func (planBrokerColdDirInfoFixture) IsDir() bool { return true }

type checkpointCatalogFixtureObject struct {
	path         string
	info         os.FileInfo
	allowSymlink bool
}

type checkpointCatalogFixture struct {
	plan            CheckpointLaunchPlan
	paths           checkpointPlanBrokerPaths
	workerPath      string
	workerInfo      os.FileInfo
	workerMode      os.FileMode
	owned           []checkpointCatalogFixtureObject
	cleanupAttempted bool
	cleanupOutcome   error
	preserve         bool
}

func (f *checkpointCatalogFixture) remember(path string, allowSymlink bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	f.owned = append(f.owned, checkpointCatalogFixtureObject{path: path, info: info, allowSymlink: allowSymlink})
	return nil
}

func (f *checkpointCatalogFixture) cleanup() error {
	if f.cleanupAttempted {
		return f.cleanupOutcome
	}
	f.cleanupAttempted = true
	if f.preserve {
		f.cleanupOutcome = errors.New("catalog fixture cleanup is uncertain; preserving held fixture")
		return f.cleanupOutcome
	}
	for index := len(f.owned) - 1; index >= 0; index-- {
		item := f.owned[index]
		current, err := os.Lstat(item.path)
		if err != nil || !os.SameFile(item.info, current) || current.Mode()&os.ModeSymlink != 0 && !item.allowSymlink {
			f.cleanupOutcome = errors.New("catalog fixture identity changed; preserving remaining paths")
			return f.cleanupOutcome
		}
		if current.IsDir() {
			entries, readErr := os.ReadDir(item.path)
			if readErr != nil || len(entries) != 0 {
				f.cleanupOutcome = errors.New("catalog fixture directory is not empty; preserving it")
				return f.cleanupOutcome
			}
		}
		if err := os.Remove(item.path); err != nil {
			f.cleanupOutcome = errors.New("catalog fixture path could not be removed nonrecursively; preserving it")
			return f.cleanupOutcome
		}
		if _, err := os.Lstat(item.path); !os.IsNotExist(err) {
			f.cleanupOutcome = errors.New("catalog fixture path absence could not be confirmed")
			return f.cleanupOutcome
		}
	}
	return nil
}

func (f *checkpointCatalogFixture) nonExecutableParserControl(t *testing.T) {
	t.Helper()
	held, err := os.Lstat(f.workerPath)
	if err != nil || !os.SameFile(f.workerInfo, held) || held.Mode().Perm() != f.workerMode.Perm() {
		f.preserve = true
		t.Fatal("held executable changed before the non-executable parser control")
	}
	restore := func() error {
		current, statErr := os.Lstat(f.workerPath)
		if statErr != nil || !os.SameFile(f.workerInfo, current) {
			f.preserve = true
			return errors.New("original executable inode changed; fixture preserved")
		}
		if chmodErr := os.Chmod(f.workerPath, f.workerMode); chmodErr != nil {
			f.preserve = true
			return errors.New("original executable mode restore failed; fixture preserved")
		}
		restored, statErr := os.Lstat(f.workerPath)
		if statErr != nil || !os.SameFile(f.workerInfo, restored) || restored.Mode().Perm() != f.workerMode.Perm() {
			f.preserve = true
			return errors.New("original executable inode or mode did not verify after restore; fixture preserved")
		}
		return nil
	}
	if err := os.Chmod(f.workerPath, f.workerMode.Perm()&^0o111); err != nil {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("held executable could not be changed to the non-executable parser control mode")
	}
	mutated, err := os.Lstat(f.workerPath)
	if err != nil || !os.SameFile(f.workerInfo, mutated) || mutated.Mode().Perm()&0o111 != 0 {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("non-executable parser control did not alter only the held executable mode")
	}
	planBytes, err := parseCatalogPlanBytes(t, f.plan)
	if err != nil {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("canonical parser control bytes could not be prepared")
	}
	catalog := checkpointPlanCatalog{Version: 1, Entries: []checkpointPlanCatalogEntry{{CatalogID: "victim-v1", ModelID: "victim", WorkloadID: "workload-a", WorkloadRevision: 3, PlanSHA256: sha256Hex(planBytes), PlanBase64: base64.StdEncoding.EncodeToString(planBytes)}}}
	catalogBytes, catalogErr := json.Marshal(catalog)
	var verified checkpointPlanCatalog
	if catalogErr != nil || json.Unmarshal(catalogBytes, &verified) != nil || len(verified.Entries) != 1 || verified.Entries[0].PlanSHA256 != sha256Hex(planBytes) {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("non-executable catalog bytes were not canonical")
	}
	decodedPlan, decodeErr := base64.StdEncoding.DecodeString(verified.Entries[0].PlanBase64)
	if decodeErr != nil || !bytes.Equal(decodedPlan, planBytes) || sha256Hex(decodedPlan) != verified.Entries[0].PlanSHA256 {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("non-executable catalog base64 or digest was not exact")
	}
	if _, err := ParseCheckpointLaunchPlan(decodedPlan); err == nil {
		if restoreErr := restore(); restoreErr != nil {
			t.Fatal("non-executable parser control and mode restoration are uncertain; fixture preserved")
		}
		t.Fatal("canonical parser accepted the held non-executable file")
	}
	if err := restore(); err != nil {
		t.Fatal("original executable mode could not be restored; fixture preserved")
	}
}

func parseCatalogPlanBytes(t *testing.T, plan CheckpointLaunchPlan) ([]byte, error) {
	t.Helper()
	planBytes, err := json.Marshal(plan)
	if err != nil {
		return nil, errors.New("catalog parser control plan could not be encoded canonically")
	}
	digest := sha256Hex(planBytes)
	encoded := base64.StdEncoding.EncodeToString(planBytes)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded || sha256Hex(decoded) != digest || !bytes.Equal(decoded, planBytes) {
		return nil, errors.New("catalog parser control plan bytes, digest, or base64 were not canonical")
	}
	return decoded, nil
}

func newCheckpointCatalogFixture(t *testing.T) *checkpointCatalogFixture {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("canonical catalog fixture requires the existing root-only private-fixture contract")
	}
	t.Setenv("VRAM_PLAN_BROKER_CPU_OPT_IN", "I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS")
	nodeUser, err := user.LookupId("65534")
	if err != nil || nodeUser.Uid != "65534" {
		t.Fatal("canonical catalog fixture requires the existing fixed UID 65534")
	}
	gidValue, err := strconv.ParseUint(nodeUser.Gid, 10, 32)
	if err != nil || gidValue == 0 {
		t.Fatal("canonical catalog fixture requires the fixed node group")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("canonical catalog fixture nonce could not be generated")
	}
	root := filepath.Join(os.TempDir(), "vram-plan-relaunch-cpu-"+hex.EncodeToString(nonce[:]))
	if err := os.Mkdir(root, 0o711); err != nil {
		t.Fatal("canonical catalog fixture root could not be created")
	}
	fixture := &checkpointCatalogFixture{}
	if err := fixture.remember(root, false); err != nil {
		t.Fatal("canonical catalog fixture root identity could not be captured")
	}
	t.Cleanup(func() {
		if !fixture.cleanupAttempted {
			if err := fixture.cleanup(); err != nil {
				t.Errorf("canonical catalog fixture cleanup failed: %v", err)
			}
		}
	})
	if err := os.Chown(root, 0, 0); err != nil {
		t.Fatal("canonical catalog fixture root ownership could not be pinned")
	}
	if err := os.Chmod(root, 0o711); err != nil {
		t.Fatal("canonical catalog fixture root identity could not be pinned")
	}
	paths := checkpointPlanBrokerPaths{
		Socket: filepath.Join(root, "run", "plan.sock"), RuntimeDir: filepath.Join(root, "run"),
		Catalog: filepath.Join(root, "etc", "checkpoint-plan-catalog.json"), ActivePlan: filepath.Join(root, "etc", "active-plan.json"),
		PrivateKey: filepath.Join(root, "var", "private", "ed25519.key"), PublicKey: filepath.Join(root, "var", "public", "ed25519.pub"),
		Journal: filepath.Join(root, "var", "private", "operations.json"), ReceiptDir: filepath.Join(root, "var", "public", "receipts"),
		StopPrivateKey: filepath.Join(root, "var", "stop-private", "ed25519.key"), StopPublicKey: filepath.Join(root, "var", "stop-public", "ed25519.pub"),
		StopReceiptDir: filepath.Join(root, "var", "stop-public", "receipts"), NodeConfig: filepath.Join(root, "etc", "node-agent.yaml"),
		NodeEnv: filepath.Join(root, "etc", "node-agent.env"), NodeState: filepath.Join(root, "var", "node", "commands.json"),
		NodeStateDir: filepath.Join(root, "var", "node"), NodeUID: 65534, NodeGID: uint32(gidValue),
		fixtureRoot: root, fixtureUnit: filepath.Base(root) + ".service", privateFixture: true,
	}
	directories := []struct {
		relative string
		uid, gid int
		mode     os.FileMode
	}{
		{"etc", 0, 0, 0o755}, {"var", 0, 0, 0o711}, {"var/private", 0, 0, 0o700},
		{"var/public", 0, 0, 0o755}, {"var/public/receipts", 0, int(gidValue), 0o750},
		{"var/stop-private", 0, 0, 0o700}, {"var/stop-public", 0, int(gidValue), 0o750},
		{"var/stop-public/receipts", 0, int(gidValue), 0o750}, {"var/node", 65534, int(gidValue), 0o700},
		{"run", 0, int(gidValue), 0o750}, {"var/custody", 0, 0, 0o700},
		{"var/snapshots", 0, 0, 0o700}, {"models", 0, 0, 0o755},
	}
	for _, directory := range directories {
		path := filepath.Join(root, directory.relative)
		if err := os.Mkdir(path, directory.mode); err != nil || fixture.remember(path, false) != nil {
			t.Fatal("canonical catalog fixture directory could not be created and held")
		}
		if os.Chown(path, directory.uid, directory.gid) != nil || os.Chmod(path, directory.mode) != nil {
			t.Fatal("canonical catalog fixture directory could not be identity-pinned")
		}
	}
	modelPath := filepath.Join(root, "models", "victim.gguf")
	modelBody := []byte("held canonical catalog model fixture")
	executablePath := filepath.Join(root, "worker")
	executableBody := []byte("#!/bin/sh\nexit 0\n")
	for _, file := range []struct {
		path string
		body []byte
		mode os.FileMode
	}{{modelPath, modelBody, 0o600}, {executablePath, executableBody, 0o755}} {
		handle, err := os.OpenFile(file.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal("canonical catalog fixture file could not be created and held")
		}
		if fixture.remember(file.path, false) != nil {
			_ = handle.Close()
			t.Fatal("canonical catalog fixture file identity could not be held")
		}
		written, writeErr := handle.Write(file.body)
		closeErr := handle.Close()
		if writeErr != nil || written != len(file.body) || closeErr != nil {
			t.Fatal("canonical catalog fixture file bytes could not be written exactly")
		}
		if os.Chown(file.path, 0, 0) != nil || os.Chmod(file.path, file.mode) != nil {
			t.Fatal("canonical catalog fixture file could not be identity-pinned")
		}
	}
	plan := checkpointPlacementFixture()
	plan.Model = CheckpointLaunchModel{Path: modelPath, SHA256: sha256Hex(modelBody), Bytes: int64(len(modelBody))}
	plan.Executable = CheckpointLaunchExecutable{Path: executablePath, SHA256: sha256Hex(executableBody)}
	plan.Custody.Root = filepath.Join(root, "var", "custody")
	plan.SnapshotRoot = filepath.Join(root, "var", "snapshots")
	fixture.plan = plan
	fixture.paths = paths
	fixture.workerPath = executablePath
	fixture.workerInfo, err = os.Lstat(executablePath)
	if err != nil {
		t.Fatal("canonical catalog worker identity could not be rechecked")
	}
	fixture.workerMode = fixture.workerInfo.Mode()
	for _, alias := range []struct{ path, target string }{
		{filepath.Join(root, "models", "urgent.gguf"), modelPath},
		{filepath.Join(root, "worker-link"), executablePath},
	} {
		if err := os.Symlink(alias.target, alias.path); err != nil || fixture.remember(alias.path, true) != nil {
			t.Fatal("owned catalog symlink alias could not be held")
		}
	}
	return fixture
}

func TestCheckpointPlanCatalogRequiresCanonicalApprovedV2Bytes(t *testing.T) {
	fixture := newCheckpointCatalogFixture(t)
	if !checkpointPlanBrokerPrivateFixturePathSet(fixture.paths) {
		t.Fatal("canonical catalog fixture does not match the existing private path set")
	}
	planBytes, err := parseCatalogPlanBytes(t, fixture.plan)
	if err != nil {
		t.Fatal("canonical catalog plan bytes could not be prepared")
	}
	digest := sha256Hex(planBytes)
	catalog := checkpointPlanCatalog{Version: 1, Entries: []checkpointPlanCatalogEntry{{CatalogID: "victim-v1", ModelID: "victim", WorkloadID: "workload-a", WorkloadRevision: 3, PlanSHA256: digest, PlanBase64: base64.StdEncoding.EncodeToString(planBytes)}}}
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal("canonical catalog envelope could not be encoded")
	}
	_, entries, err := decodeCheckpointPlanCatalog(raw, fixture.paths)
	if err != nil || entries["victim-v1"].CatalogID != "victim-v1" {
		t.Fatalf("valid approved plan rejected: %v", err)
	}
	if _, _, err := decodeCheckpointPlanCatalog(raw); err == nil {
		t.Fatal("private-root catalog was accepted by the production fixed-root validator")
	}
	expectFilesystemReject := func(label string, mutant CheckpointLaunchPlan) {
		t.Helper()
		encoded, encodeErr := parseCatalogPlanBytes(t, mutant)
		if encodeErr != nil || len(encoded) == 0 {
			t.Fatalf("%s control did not retain canonical plan digest/base64", label)
		}
		mutantCatalog := checkpointPlanCatalog{Version: 1, Entries: []checkpointPlanCatalogEntry{{CatalogID: "victim-v1", ModelID: "victim", WorkloadID: "workload-a", WorkloadRevision: 3, PlanSHA256: sha256Hex(encoded), PlanBase64: base64.StdEncoding.EncodeToString(encoded)}}}
		catalogBytes, catalogErr := json.Marshal(mutantCatalog)
		var verified checkpointPlanCatalog
		if catalogErr != nil || json.Unmarshal(catalogBytes, &verified) != nil || len(verified.Entries) != 1 || verified.Entries[0].PlanSHA256 != sha256Hex(encoded) {
			t.Fatalf("%s catalog envelope did not retain its exact plan digest", label)
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(verified.Entries[0].PlanBase64)
		if decodeErr != nil || !bytes.Equal(decoded, encoded) || sha256Hex(decoded) != verified.Entries[0].PlanSHA256 {
			t.Fatalf("%s catalog envelope did not retain canonical base64 plan bytes", label)
		}
		if _, parseErr := ParseCheckpointLaunchPlan(decoded); parseErr == nil {
			t.Errorf("canonical parser accepted %s filesystem mutant", label)
		}
	}
	missingModel := fixture.plan
	missingModel.Model.Path = filepath.Join(fixture.paths.fixtureRoot, "models", "missing.gguf")
	expectFilesystemReject("missing model", missingModel)
	missingExecutable := fixture.plan
	missingExecutable.Executable.Path = filepath.Join(fixture.paths.fixtureRoot, "missing-worker")
	expectFilesystemReject("missing executable", missingExecutable)
	symlinkModel := fixture.plan
	symlinkModel.Model.Path = filepath.Join(fixture.paths.fixtureRoot, "models", "urgent.gguf")
	expectFilesystemReject("symlink model", symlinkModel)
	symlinkExecutable := fixture.plan
	symlinkExecutable.Executable.Path = filepath.Join(fixture.paths.fixtureRoot, "worker-link")
	expectFilesystemReject("symlink executable", symlinkExecutable)
	fixture.nonExecutableParserControl(t)
	mutants := [][]byte{append(append([]byte(nil), raw...), ' '), []byte(strings.Replace(string(raw), "victim-v1", "../victim", 1)), []byte(strings.Replace(string(raw), digest, strings.Repeat("0", 64), 1))}
	for i, mutant := range mutants {
		if _, _, err := decodeCheckpointPlanCatalog(mutant, fixture.paths); err == nil {
			t.Errorf("catalog mutant %d was accepted", i)
		}
	}
	if err := fixture.cleanup(); err != nil {
		t.Fatalf("canonical catalog fixture cleanup failed: %v", err)
	}
}

type planBrokerRequestFaultConn struct {
	written    []byte
	writeLimit int
	writeErr   error
	closeErr   error
	closeCalls int
}

func (c *planBrokerRequestFaultConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	n := len(p)
	if c.writeLimit > 0 && c.writeLimit < n {
		n = c.writeLimit
	}
	c.written = append(c.written, p[:n]...)
	return n, nil
}

func (c *planBrokerRequestFaultConn) CloseWrite() error {
	c.closeCalls++
	return c.closeErr
}

func TestPlanBrokerRequestHalfCloseUnixStream(t *testing.T) {
	root, err := os.MkdirTemp("", "plan-broker-transport-")
	if err != nil {
		t.Fatal("bounded private Unix fixture directory could not be created")
	}
	rootHandle, err := os.Open(root)
	if err != nil {
		t.Fatal("bounded private Unix fixture directory could not be held; preserving unique private fixture directory")
	}
	rootInfo, err := rootHandle.Stat()
	if err != nil || !rootInfo.IsDir() {
		_ = rootHandle.Close()
		t.Fatal("bounded private Unix fixture directory identity could not be captured; preserving unique private fixture directory")
	}
	socket := filepath.Join(root, "request.sock")
	var listener *net.UnixListener
	var client *net.UnixConn
	var socketInfo os.FileInfo
	type serverCloseResult struct {
		known    bool
		accepted bool
		err      error
	}
	var serverCloseOutcome chan serverCloseResult
	serverClosed := make(chan struct{})
	close(serverClosed)
	cleanupAttempted := false
	cleanup := func() error {
		if cleanupAttempted {
			return errors.New("bounded Unix fixture cleanup was already attempted")
		}
		cleanupAttempted = true
		var cleanupErr error
		if listener != nil {
			if err := listener.Close(); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
		if client != nil {
			if err := client.Close(); err != nil && cleanupErr == nil {
				cleanupErr = err
			}
		}
		select {
		case <-serverClosed:
		case <-time.After(5 * time.Second):
			_ = rootHandle.Close()
			return errors.New("bounded Unix server did not close within fixed five seconds; preserving fixture")
		}
		closeState := "not-created"
		if serverCloseOutcome != nil {
			closeState = "unknown"
			select {
			case outcome, ok := <-serverCloseOutcome:
				if !ok || !outcome.known {
					_ = rootHandle.Close()
					return errors.New("bounded Unix accepted-server close outcome is unknown; preserving fixture")
				}
				if !outcome.accepted {
					closeState = "not-created"
				} else if outcome.err != nil {
					closeState = "close-failed"
				} else {
					closeState = "closed"
				}
			default:
				_ = rootHandle.Close()
				return errors.New("bounded Unix accepted-server close outcome was not published; preserving fixture")
			}
		}
		if closeState == "unknown" || closeState == "close-failed" {
			_ = rootHandle.Close()
			return errors.New("bounded Unix accepted-server close did not succeed; preserving fixture")
		}
		if cleanupErr != nil {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture close failed; preserving fixture")
		}
		currentRoot, err := os.Lstat(root)
		if err != nil || !os.SameFile(rootInfo, currentRoot) || !currentRoot.IsDir() {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture root identity changed; preserving fixture")
		}
		currentSocket, err := os.Lstat(socket)
		if socketInfo != nil {
			if err != nil || !os.SameFile(socketInfo, currentSocket) || currentSocket.Mode()&os.ModeSocket == 0 {
				_ = rootHandle.Close()
				return errors.New("bounded Unix socket identity changed; preserving fixture")
			}
			if err := os.Remove(socket); err != nil {
				_ = rootHandle.Close()
				return errors.New("bounded Unix socket could not be removed nonrecursively; preserving fixture")
			}
			if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
				_ = rootHandle.Close()
				return errors.New("bounded Unix socket absence was not confirmed; preserving fixture")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			_ = rootHandle.Close()
			return errors.New("unexpected Unix socket remains in fixture; preserving fixture")
		}
		entries, err := os.ReadDir(root)
		if err != nil || len(entries) != 0 {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture root contains an unexpected entry; preserving fixture")
		}
		currentRoot, err = os.Lstat(root)
		if err != nil || !os.SameFile(rootInfo, currentRoot) {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture root identity changed before removal; preserving fixture")
		}
		if err := os.Remove(root); err != nil {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture root could not be removed nonrecursively; preserving fixture")
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			_ = rootHandle.Close()
			return errors.New("bounded Unix fixture root absence was not confirmed")
		}
		return rootHandle.Close()
	}
	defer func() {
		if !cleanupAttempted {
			if err := cleanup(); err != nil {
				t.Errorf("bounded Unix fixture cleanup failed: %v", err)
			}
		}
	}()
	if currentRoot, err := os.Lstat(root); err != nil || !os.SameFile(rootInfo, currentRoot) {
		t.Fatal("bounded private Unix fixture root was replaced before listener creation")
	}
	listener, err = net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal("bounded Unix listener could not be created")
	}
	listener.SetUnlinkOnClose(false)
	socketInfo, err = os.Lstat(socket)
	if err != nil || socketInfo.Mode()&os.ModeSocket == 0 {
		t.Fatal("bounded Unix socket identity could not be captured")
	}
	type serverResult struct {
		frame string
		err   error
	}
	serverDone := make(chan serverResult, 1)
	serverCloseOutcome = make(chan serverCloseResult, 1)
	serverClosed = make(chan struct{})
	go func() {
		server, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverCloseOutcome <- serverCloseResult{known: true, accepted: false}
			serverDone <- serverResult{err: acceptErr}
			close(serverClosed)
			return
		}
		result := serverResult{}
		defer func() {
			closeErr := server.Close()
			serverCloseOutcome <- serverCloseResult{known: true, accepted: true, err: closeErr}
			result.err = errors.Join(result.err, closeErr)
			serverDone <- result
			close(serverClosed)
		}()
		if deadlineErr := server.SetDeadline(time.Now().Add(2 * time.Second)); deadlineErr != nil {
			result.err = deadlineErr
			return
		}
		frame, readErr := io.ReadAll(io.LimitReader(server, checkpointPlanRelaunchMaxFrame+1))
		if readErr != nil || len(frame) == 0 || len(frame) > checkpointPlanRelaunchMaxFrame || string(frame) != "ordinary bounded request\n" {
			result = serverResult{frame: string(frame), err: errors.New("ordinary bounded request did not reach EOF with its exact frame")}
			return
		}
		response := []byte("{\"accepted\":true}\n")
		written, writeErr := server.Write(response)
		if writeErr != nil || written != len(response) {
			result = serverResult{frame: string(frame), err: errors.New("bounded Unix server response was incomplete")}
			return
		}
		result = serverResult{frame: string(frame)}
	}()
	client, err = net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal("bounded Unix client could not connect")
	}
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal("bounded Unix client deadline could not be set")
	}
	if err := writeCheckpointPlanBrokerRequest(client, []byte("ordinary bounded request")); err != nil {
		t.Fatalf("ordinary bounded request could not be fully written and half-closed: %v", err)
	}
	response, err := io.ReadAll(io.LimitReader(client, checkpointPlanRelaunchMaxFrame+1))
	var result serverResult
	select {
	case result = <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded Unix server did not settle after the request half-close")
	}
	if err != nil || string(response) != "{\"accepted\":true}\n" {
		t.Fatalf("ordinary request did not receive response after half-close: %v", err)
	}
	if result.err != nil || result.frame != "ordinary bounded request\n" {
		t.Fatalf("bounded Unix server rejected the framed request: %v", result.err)
	}
	select {
	case <-serverClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("bounded Unix server did not close after reporting its result")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("bounded Unix fixture cleanup failed: %v", err)
	}
}

func TestPlanBrokerRequestHalfCloseRejectsWriteFaults(t *testing.T) {
	request := []byte("bounded")
	writeFailure := errors.New("injected write failure")
	writeConn := &planBrokerRequestFaultConn{writeErr: writeFailure}
	if err := writeCheckpointPlanBrokerRequest(writeConn, request); !errors.Is(err, writeFailure) || writeConn.closeCalls != 0 {
		t.Fatal("request write error was not returned before half-close")
	}
	shortConn := &planBrokerRequestFaultConn{writeLimit: 1}
	if err := writeCheckpointPlanBrokerRequest(shortConn, request); !errors.Is(err, io.ErrShortWrite) || shortConn.closeCalls != 0 {
		t.Fatal("short request write was not rejected before half-close")
	}
	closeFailure := errors.New("injected CloseWrite failure")
	closeConn := &planBrokerRequestFaultConn{closeErr: closeFailure}
	if err := writeCheckpointPlanBrokerRequest(closeConn, request); !errors.Is(err, closeFailure) || closeConn.closeCalls != 1 || string(closeConn.written) != "bounded\n" {
		t.Fatal("CloseWrite error was not returned after one exact complete frame")
	}
	completeConn := &planBrokerRequestFaultConn{}
	if err := writeCheckpointPlanBrokerRequest(completeConn, request); err != nil || completeConn.closeCalls != 1 || string(completeConn.written) != "bounded\n" {
		t.Fatal("complete bounded request did not write the newline and half-close exactly once")
	}
}

func TestPlanBrokerUnitParserRequiresCompleteFixedProperties(t *testing.T) {
	unitControlGroup := filepath.Join("/system.slice", checkpointPlanBrokerUnitName(checkpointPlanBrokerPaths{}))
	valid := []byte(fmt.Sprintf("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=%s\nActiveState=inactive\nSubState=dead\n", unitControlGroup))
	unit, err := parseCheckpointPlanBrokerUnitState(valid)
	if err != nil || unit.MainPID != 0 || unit.Active != "inactive" || unit.Invocation == "" {
		t.Fatalf("valid exact inactive unit state rejected: %#v, %v", unit, err)
	}
	active := []byte(fmt.Sprintf("MainPID=42\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=%s\nActiveState=active\nSubState=running\n", unitControlGroup))
	activeUnit, err := parseCheckpointPlanBrokerUnitState(active)
	if err != nil || activeUnit.MainPID != 42 || activeUnit.Active != "active" || activeUnit.Invocation == "" || activeUnit.ControlGroup != unitControlGroup {
		t.Fatalf("valid active unit with a live MainPID was rejected: %#v, %v", activeUnit, err)
	}
	inconsistentActive := []byte(strings.Replace(string(active), "ActiveState=active", "ActiveState=inactive", 1))
	if _, err := parseCheckpointPlanBrokerUnitState(inconsistentActive); err == nil {
		t.Fatal("inactive unit state with a live MainPID was accepted")
	}
	mutants := [][]byte{
		[]byte(strings.Replace(string(valid), "MainPID=0", "MainPID=1", 1)),
		[]byte(strings.Replace(string(valid), "ActiveState=inactive", "ActiveState=active", 1)),
		[]byte(strings.Replace(string(valid), "ControlGroup=", "Other=", 1)),
		[]byte(strings.Replace(string(valid), "SubState=dead\n", "", 1)),
		[]byte(strings.Replace(string(valid), "MainPID=0\n", "MainPID=0\nMainPID=0\n", 1)),
		append(append([]byte(nil), valid...), 'x'),
	}
	for i, mutant := range mutants {
		if _, err := parseCheckpointPlanBrokerUnitState(mutant); err == nil {
			t.Errorf("unit-state parser mutant %d was accepted", i)
		}
	}
	stopped := []byte(fmt.Sprintf("MainPID=0\nInvocationID=0123456789abcdef0123456789abcdef\nControlGroup=%s\nActiveState=inactive\nSubState=dead\nLoadState=loaded\n", unitControlGroup))
	if got, err := parseCheckpointPlanBrokerStoppedState(stopped); err != nil || got.MainPID != 0 || got.Invocation != "0123456789abcdef0123456789abcdef" || got.Load != "loaded" {
		t.Fatalf("exact loaded stopped observation rejected: %#v, %v", got, err)
	}
	blankPrior := []byte("MainPID=0\nInvocationID=\nControlGroup=\nActiveState=inactive\nSubState=dead\nLoadState=loaded\n")
	if got, err := parseCheckpointPlanBrokerStoppedState(blankPrior); err != nil || got.Invocation != "" || got.ControlGroup != "" {
		t.Fatalf("actual blank stopped identity fields were not preserved: %#v, %v", got, err)
	}
	prior := ownedStopReceipt{WorkerPID: 42, WorkerStartTicks: 9, InvocationID: "0123456789abcdef0123456789abcdef", ControlGroup: unitControlGroup, SignalSent: true, ReleaseTerminal: true}
	if err := verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, stopped), checkpointPlanBrokerPaths{}, prior); err != nil {
		t.Fatalf("stopped observation did not join exact signed prior identity: %v", err)
	}
	if err := verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, blankPrior), checkpointPlanBrokerPaths{}, prior); err != nil {
		t.Fatalf("both actually blank stopped identity fields were not accepted with prior authority: %v", err)
	}
	wrongPrior := prior
	wrongPrior.ControlGroup = filepath.Join("/system.slice", "other.service")
	if err := verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, stopped), checkpointPlanBrokerPaths{}, wrongPrior); err == nil {
		t.Fatal("stopped observation accepted a prior signed for a different fixed unit cgroup")
	}
	stoppedMutants := [][]byte{
		[]byte(strings.Replace(string(stopped), "LoadState=loaded", "LoadState=not-found", 1)),
		[]byte(strings.Replace(string(stopped), "SubState=dead", "SubState=failed", 1)),
		[]byte(strings.Replace(string(stopped), "MainPID=0", "MainPID=7", 1)),
		[]byte(strings.Replace(string(stopped), "ActiveState=inactive", "ActiveState=active", 1)),
		[]byte(strings.Replace(string(stopped), "LoadState=loaded\n", "LoadState=loaded\nPrivatePath=/secret\n", 1)),
		[]byte(strings.Replace(string(stopped), "SubState=dead\n", "SubState=dead\nLoadState=loaded\n", 1)),
		append(append([]byte(nil), stopped...), 'x'),
	}
	for i, mutant := range stoppedMutants {
		if _, err := parseCheckpointPlanBrokerStoppedState(mutant); err == nil {
			t.Errorf("stopped-state parser mutant %d was accepted", i)
		}
	}
	for i, mutant := range [][]byte{
		[]byte(strings.Replace(string(stopped), "ControlGroup="+unitControlGroup, "ControlGroup=/system.slice/other.service", 1)),
		[]byte(strings.Replace(string(stopped), "InvocationID=0123456789abcdef0123456789abcdef", "InvocationID=", 1)),
		[]byte(strings.Replace(string(stopped), "ControlGroup="+unitControlGroup, "ControlGroup=", 1)),
		[]byte(strings.Replace(string(blankPrior), "ControlGroup=\n", "ControlGroup="+unitControlGroup+"\n", 1)),
	} {
		observed, parseErr := parseCheckpointPlanBrokerStoppedState(mutant)
		if parseErr != nil {
			t.Errorf("structural stopped observation control %d failed to parse: %v", i, parseErr)
			continue
		}
		if verifyCheckpointPlanBrokerStoppedObservation(observed, checkpointPlanBrokerPaths{}, prior) == nil {
			t.Errorf("stopped observation authority mutant %d was accepted", i)
		}
	}
	testPlanBrokerPriorStopResultControls(t)
}

func testPlanBrokerPriorStopResultControls(t *testing.T) {
	t.Helper()
	const secret = "ssssssssssssssssssssssssssssssssssssssss"
	paths := checkpointPlanBrokerPaths{}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate prior stop test key")
	}
	command, err := ownedStopFixtureCommand("node-a", strings.Repeat("a", 64), "prior.kv", strings.Repeat("b", 64), "epoch-01", secret)
	if err != nil {
		t.Fatal("create exact signed prior stop command")
	}
	command.ID, command.IdempotencyKey = "prior-stop-id", "prior-stop-key"
	command.Args["operation_id"] = "operation-01"
	command.Args["step_id"] = "victim_stop"
	command.Args["target_id"] = "node-a-server-0"
	command.Args["accelerator_id"] = "gpu-0"
	command.Args["workload_id"] = "workload-01"
	command.Args["workload_revision"] = int64(2)
	command.Args["recovery_epoch"] = "epoch-01"
	command.Args["fencing_token"] = int64(8)
	command.Signature, err = wsproto.SignCommand(command, []byte(secret))
	if err != nil {
		t.Fatal("sign exact prior stop command")
	}
	originalWire, err := wsproto.CanonicalCommandEnvelope(command)
	if err != nil {
		t.Fatal("canonicalize prior stop command")
	}
	request, err := ownedStopFixtureRequest(command, public, secret)
	if err != nil {
		t.Fatal("bind prior stop command and root key")
	}
	receiptRaw, err := signOwnedStopFixtureReceipt(command, request, private)
	if err != nil {
		t.Fatal("sign prior stop receipt")
	}
	var receipt ownedStopReceipt
	if json.Unmarshal(receiptRaw, &receipt) != nil {
		t.Fatal("decode prior stop receipt")
	}
	receipt.ControlGroup = filepath.Join("/system.slice", checkpointPlanBrokerUnitName(paths))
	receipt.Signature = ""
	unsignedReceipt, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal("encode prior stop receipt identity")
	}
	receipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsignedReceipt)))
	receiptRaw, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal("encode signed prior stop receipt")
	}
	priorDigest := sha256Hex(receiptRaw)
	plan := wsproto.CommandPayload{ID: "urgent-id", NodeID: command.NodeID, Command: checkpointPlanRelaunchUrgentCommand, Args: map[string]any{
		"operation_id": "operation-01", "accelerator_id": "gpu-0", "recovery_epoch": "epoch-01", "fencing_token": int64(8),
		"target_id": "node-a-server-0", "workload_id": "workload-01", "workload_revision": int64(2),
		"prior_command_id": command.ID, "prior_idempotency_key": command.IdempotencyKey, "prior_receipt_sha256": priorDigest,
	}}
	step := ownedStopStepState{CommandID: command.ID, IdempotencyKey: command.IdempotencyKey, EnvelopeSHA256: sha256Hex(originalWire), PinnedRootStopPublicKey: append([]byte(nil), public...), Status: "acknowledged", ReceiptSHA256: priorDigest}
	operation := ownedStopOperationState{OperationID: "operation-01", AcceleratorID: "gpu-0", Fence: 8, RecoveryEpoch: "epoch-01", UsedOperationIDs: map[string]bool{"operation-01": true}, Steps: map[string]ownedStopStepState{"victim_stop": step}}
	persistedStep := step
	persistedStep.PinnedRootStopPublicKey = append([]byte(nil), step.PinnedRootStopPublicKey...)
	persistedOperation := operation
	persistedOperation.UsedOperationIDs = map[string]bool{"operation-01": true}
	persistedOperation.Steps = map[string]ownedStopStepState{"victim_stop": persistedStep}
	state := commandStatePayload{
		Results: map[string]wsproto.CommandResultPayload{command.ID: priorStopResult(command, originalWire, public, receiptRaw)},
		OwnedStopOperations: map[string]ownedStopOperationState{"gpu-0": persistedOperation},
	}
	copyColdState := func() commandStatePayload {
		mutant := state
		mutant.Results = make(map[string]wsproto.CommandResultPayload, len(state.Results))
		for key, value := range state.Results {
			mutant.Results[key] = value
		}
		mutant.OwnedStopOperations = make(map[string]ownedStopOperationState, len(state.OwnedStopOperations))
		for key, value := range state.OwnedStopOperations {
			value.UsedOperationIDs = map[string]bool{}
			for operationID, used := range state.OwnedStopOperations[key].UsedOperationIDs {
				value.UsedOperationIDs[operationID] = used
			}
			value.Steps = make(map[string]ownedStopStepState, len(state.OwnedStopOperations[key].Steps))
			for stepID, storedStep := range state.OwnedStopOperations[key].Steps {
				storedStep.PinnedRootStopPublicKey = append([]byte(nil), storedStep.PinnedRootStopPublicKey...)
				value.Steps[stepID] = storedStep
			}
			mutant.OwnedStopOperations[key] = value
		}
		return mutant
	}
	if err := verifyCheckpointPlanBrokerPriorStopResult(state, paths, plan, operation, step, receiptRaw, public, secret); err != nil {
		t.Fatalf("known exact durable prior stop proof was rejected: %v", err)
	}
	if cold, coldErr := verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, plan, operation, step, receiptRaw, public, secret, os.ErrNotExist); coldErr != nil || cold.WorkerPID != receipt.WorkerPID {
		t.Fatalf("known exact cold prior-stop proof was rejected: %v", coldErr)
	}
	if _, err := verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, plan, operation, step, receiptRaw, public, secret, nil); err == nil {
		t.Fatal("cold prior-stop proof accepted a still-present original process")
	}
	if _, err := verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, plan, operation, step, receiptRaw, append(ed25519.PublicKey(nil), public[:len(public)-1]...), secret, os.ErrNotExist); err == nil {
		t.Fatal("cold prior-stop proof accepted a truncated pinned key")
	}
	missingResult := copyColdState()
	missingResult.Results = map[string]wsproto.CommandResultPayload{}
	if _, err := verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(missingResult, paths, plan, operation, step, receiptRaw, public, secret, os.ErrNotExist); err == nil {
		t.Fatal("cold prior-stop proof accepted a lost durable predecessor")
	}
	staleReceipt := append([]byte(nil), receiptRaw...)
	staleReceipt[len(staleReceipt)-1] ^= 1
	if _, err := verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, plan, operation, step, staleReceipt, public, secret, os.ErrNotExist); err == nil {
		t.Fatal("cold prior-stop proof accepted a stale receipt body")
	}
	validStale := receipt
	validStale.ManagedPlanSHA256 = strings.Repeat("f", 64)
	validStale.Signature = ""
	validStaleUnsigned, err := json.Marshal(validStale)
	if err != nil {
		t.Fatal("encode valid stale receipt mutant")
	}
	validStale.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(validStaleUnsigned)))
	validStaleRaw, err := json.Marshal(validStale)
	if err != nil || verifyOwnedStopReceipt(validStaleRaw, public, originalWire, secret) != nil {
		t.Fatal("valid changed receipt must retain its signature and original command join")
	}

	stopPaths := checkpointPlanBrokerOwnedStopPaths(paths)
	receiptPath := filepath.Join(stopPaths.ReceiptDir, ownedStopReceiptFilename(command.ID))
	safeDir := planBrokerColdDirInfoFixture{ownedStopKeyInfoFixture{mode: os.ModeDir | 0o750, stat: syscall.Stat_t{Uid: 0, Gid: stopPaths.NodeGID, Nlink: 2}}}
	coldReadCounts := map[string]int{}
	fileInfo := func(body []byte) os.FileInfo {
		return ownedStopKeyInfoFixture{mode: 0o640, size: int64(len(body)), stat: syscall.Stat_t{Uid: 0, Gid: stopPaths.NodeGID, Nlink: 1}}
	}
	makeColdIO := func(key []byte, keyErr error, dir os.FileInfo, dirErr error, pathErr error, body []byte, readErr error, bodyInfo os.FileInfo, procErr error) checkpointPlanBrokerColdStopIO {
		return checkpointPlanBrokerColdStopIO{
			readPublicKey: func(path string, gotPaths checkpointOwnedStopPaths) ([]byte, error) {
				coldReadCounts["key"]++
				if path != stopPaths.PublicKey || gotPaths.PublicKey != stopPaths.PublicKey {
					return nil, errors.New("unexpected key path")
				}
				return append(ed25519.PublicKey(nil), key...), keyErr
			},
			lstat: func(path string) (os.FileInfo, error) {
				coldReadCounts["lstat"]++
				if path != stopPaths.ReceiptDir {
					return nil, errors.New("unexpected directory path")
				}
				return dir, dirErr
			},
			pathChain: func(path string, gotPaths checkpointOwnedStopPaths, publicPath bool) error {
				coldReadCounts["path"]++
				if path != receiptPath || gotPaths.ReceiptDir != stopPaths.ReceiptDir || !publicPath {
					return errors.New("unexpected receipt path chain")
				}
				return pathErr
			},
			readReceipt: func(path string, limit int64, mode os.FileMode) ([]byte, os.FileInfo, error) {
				coldReadCounts["receipt"]++
				if path != receiptPath || limit != 16<<10 || mode != 0o640 {
					return nil, nil, errors.New("unexpected receipt read")
				}
				return append([]byte(nil), body...), bodyInfo, readErr
			},
			processStart: func(pid int) error {
				coldReadCounts["process"]++
				if pid != receipt.WorkerPID {
					return errors.New("unexpected original PID")
				}
				return procErr
			},
		}
	}
	validColdIO := makeColdIO(public, nil, safeDir, nil, nil, receiptRaw, nil, fileInfo(receiptRaw), os.ErrNotExist)
	clear(coldReadCounts)
	if cold, coldErr := checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, state, plan, secret, validColdIO); coldErr != nil || cold.WorkerPID != receipt.WorkerPID {
		t.Fatalf("known owned-IO cold wrapper path was rejected: %v", coldErr)
	}
	for _, phase := range []string{"key", "lstat", "path", "receipt", "process"} {
		if coldReadCounts[phase] != 1 {
			t.Fatalf("known owned-IO cold path did not reach exactly one %s read: %#v", phase, coldReadCounts)
		}
	}
	missingOperationState := copyColdState()
	missingOperationState.OwnedStopOperations = map[string]ownedStopOperationState{}
	clear(coldReadCounts)
	if _, err := checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, missingOperationState, plan, secret, validColdIO); err == nil || !strings.Contains(err.Error(), "cold recovery lost the exact prior stop operation") {
		t.Fatalf("missing operation was not rejected at the intended predecessor lookup: %v", err)
	}
	if len(coldReadCounts) != 0 {
		t.Fatalf("missing operation negative unexpectedly reached owned IO: %#v", coldReadCounts)
	}
	missingUnit := checkpointPlanBrokerStoppedState{MainPID: 0, Active: "inactive", Sub: "dead", Load: "not-found"}
	if err := verifyCheckpointPlanBrokerStoppedObservation(missingUnit, paths, receipt); err == nil {
		t.Fatal("cold recovery authorized the exact unit-definition-missing observation")
	}
	changedPublic := append(ed25519.PublicKey(nil), public...)
	changedPublic[0] ^= 0xff
	for _, failure := range []struct {
		name string
		io   checkpointPlanBrokerColdStopIO
		want string
	}{
		{"missing pinned key read", makeColdIO(public, os.ErrNotExist, safeDir, nil, nil, receiptRaw, nil, fileInfo(receiptRaw), os.ErrNotExist), "root stop public key is unavailable"},
		{"same-length changed pinned key", makeColdIO(changedPublic, nil, safeDir, nil, nil, receiptRaw, nil, fileInfo(receiptRaw), os.ErrNotExist), "root stop key pin changed"},
		{"unsafe owned path chain", makeColdIO(public, nil, safeDir, nil, errors.New("unsafe"), receiptRaw, nil, fileInfo(receiptRaw), os.ErrNotExist), "receipt directory is unsafe"},
		{"wrong directory owner", makeColdIO(public, nil, planBrokerColdDirInfoFixture{ownedStopKeyInfoFixture{mode: os.ModeDir | 0o750, stat: syscall.Stat_t{Uid: 1000, Gid: stopPaths.NodeGID, Nlink: 2}}}, nil, nil, receiptRaw, nil, fileInfo(receiptRaw), os.ErrNotExist), "receipt directory is unsafe"},
		{"missing receipt", makeColdIO(public, nil, safeDir, nil, nil, nil, os.ErrNotExist, nil, os.ErrNotExist), "receipt is missing"},
		{"valid signed stale receipt", makeColdIO(public, nil, safeDir, nil, nil, validStaleRaw, nil, fileInfo(validStaleRaw), os.ErrNotExist), "receipt is unavailable or changed"},
		{"wrong receipt owner", makeColdIO(public, nil, safeDir, nil, nil, receiptRaw, nil, ownedStopKeyInfoFixture{mode: 0o640, size: int64(len(receiptRaw)), stat: syscall.Stat_t{Uid: 1000, Gid: stopPaths.NodeGID, Nlink: 1}}, os.ErrNotExist), "receipt ownership or inode is unsafe"},
		{"linked receipt inode", makeColdIO(public, nil, safeDir, nil, nil, receiptRaw, nil, ownedStopKeyInfoFixture{mode: 0o640, size: int64(len(receiptRaw)), stat: syscall.Stat_t{Uid: 0, Gid: stopPaths.NodeGID, Nlink: 2}}, os.ErrNotExist), "receipt ownership or inode is unsafe"},
		{"receipt changed during held read", makeColdIO(public, nil, safeDir, nil, nil, receiptRaw, errors.New("changed during held read"), fileInfo(receiptRaw), os.ErrNotExist), "receipt is unavailable or changed"},
		{"original process state uncertain", makeColdIO(public, nil, safeDir, nil, nil, receiptRaw, nil, fileInfo(receiptRaw), errors.New("permission denied")), "original worker terminal proof is unavailable"},
	} {
		if _, err := checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, copyColdState(), plan, secret, failure.io); err == nil || !strings.Contains(err.Error(), failure.want) {
			t.Errorf("cold owned-IO %s control did not reject for %s: %v", failure.name, failure.want, err)
		}
	}
	for _, badOperation := range []ownedStopOperationState{
		func() ownedStopOperationState { bad := operation; bad.OperationID = "other-operation"; return bad }(),
		func() ownedStopOperationState { bad := operation; bad.Fence++; return bad }(),
	} {
		badState := copyColdState()
		badState.OwnedStopOperations = map[string]ownedStopOperationState{"gpu-0": badOperation}
		if _, err := checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, badState, plan, secret, validColdIO); err == nil || !strings.Contains(err.Error(), "prior root stop operation") {
			t.Error("cold owned-IO reducer accepted a lost or drifted predecessor")
		}
	}
	mutateAndRejectExpected := func(label, expected string, mutate func(*commandStatePayload, *wsproto.CommandPayload, *ownedStopOperationState, *ownedStopStepState, *[]byte, *[]byte)) {
		t.Helper()
		mutantState := state
		mutantState.Results = map[string]wsproto.CommandResultPayload{}
		for key, value := range state.Results {
			value.Result = map[string]any{}
			for field, item := range state.Results[command.ID].Result {
				value.Result[field] = item
			}
			mutantState.Results[key] = value
		}
		mutantCommand := plan
		mutantCommand.Args = map[string]any{}
		for key, value := range plan.Args {
			mutantCommand.Args[key] = value
		}
		mutantOperation := operation
		mutantOperation.UsedOperationIDs = map[string]bool{"operation-01": true}
		mutantOperation.Steps = map[string]ownedStopStepState{"victim_stop": step}
		mutantStep := step
		mutantReceipt := append([]byte(nil), receiptRaw...)
		mutantPublic := append([]byte(nil), public...)
		mutate(&mutantState, &mutantCommand, &mutantOperation, &mutantStep, &mutantReceipt, &mutantPublic)
		proofErr := verifyCheckpointPlanBrokerPriorStopResult(mutantState, paths, mutantCommand, mutantOperation, mutantStep, mutantReceipt, ed25519.PublicKey(mutantPublic), secret)
		if proofErr == nil {
			t.Errorf("durable prior stop proof accepted %s mutant", label)
		} else if expected != "" && !strings.Contains(proofErr.Error(), expected) {
			t.Errorf("durable prior stop %s mutant was rejected for the wrong reason: %v", label, proofErr)
		}
	}
	mutateAndReject := func(label string, mutate func(*commandStatePayload, *wsproto.CommandPayload, *ownedStopOperationState, *ownedStopStepState, *[]byte, *[]byte)) {
		mutateAndRejectExpected(label, "", mutate)
	}
	mutateSignedOriginalLink := func(field string, value any) func(*commandStatePayload, *wsproto.CommandPayload, *ownedStopOperationState, *ownedStopStepState, *[]byte, *[]byte) {
		return func(state *commandStatePayload, planCommand *wsproto.CommandPayload, operation *ownedStopOperationState, step *ownedStopStepState, raw *[]byte, public *[]byte) {
			result := state.Results[step.CommandID]
			wire, decodeErr := base64.StdEncoding.DecodeString(result.Result["original_envelope"].(string))
			var original wsproto.CommandPayload
			if decodeErr != nil || json.Unmarshal(wire, &original) != nil {
				t.Fatal("decode copied signed original command")
			}
			original.Args[field] = value
			original.Signature, decodeErr = wsproto.SignCommand(original, []byte(secret))
			if decodeErr != nil {
				t.Fatal("sign copied original command link mutant")
			}
			wire, _ = wsproto.CanonicalCommandEnvelope(original)
			if !wsproto.VerifyCommand(original, []byte(secret)) {
				t.Fatal("operation-link mutant command signature is invalid")
			}
			canonical, canonicalErr := wsproto.CanonicalCommandEnvelope(original)
			if canonicalErr != nil || !bytes.Equal(canonical, wire) {
				t.Fatal("operation-link mutant original command is not canonical")
			}
			result.Result["original_envelope"] = base64.StdEncoding.EncodeToString(wire)
			state.Results[step.CommandID] = result
			step.EnvelopeSHA256 = sha256Hex(wire)
			var changedReceipt ownedStopReceipt
		if json.Unmarshal(*raw, &changedReceipt) != nil {
			t.Fatal("decode signed receipt for operation-link mutant")
		}
		changedReceipt.OriginalEnvelopeSHA256 = step.EnvelopeSHA256
		changedReceipt.SigningMaterialSHA256 = ""
		changedMaterial, materialErr := wsproto.CommandSigningMaterialForOwnedStop(original)
		if materialErr != nil {
			t.Fatal("derive signed operation-link material")
		}
		changedReceipt.SigningMaterialSHA256 = sha256Hex(changedMaterial)
		changedReceipt.OperationID = fmt.Sprint(original.Args["operation_id"])
		changedReceipt.StepID = fmt.Sprint(original.Args["step_id"])
			changedReceipt.Signature = ""
			unsigned, _ := json.Marshal(changedReceipt)
			changedReceipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsigned)))
			*raw, _ = json.Marshal(changedReceipt)
			if err := verifyOwnedStopReceipt(*raw, ed25519.PublicKey(*public), wire, secret); err != nil {
				t.Fatalf("operation-link mutant receipt is not fully valid against its signed original command: %v", err)
			}
			digest := sha256Hex(*raw)
			step.ReceiptSHA256 = digest
			planCommand.Args["prior_receipt_sha256"] = digest
			result = state.Results[step.CommandID]
			result.Result["receipt"] = string(*raw)
			result.Result["receipt_sha256"] = digest
			state.Results[step.CommandID] = result
			operation.Steps["victim_stop"] = *step
		}
	}
	mutateAndRejectExpected("validly signed original operation mismatch", "durable prior stop command differs from the linked plan request", mutateSignedOriginalLink("operation_id", "other-operation"))
	mutateAndRejectExpected("validly signed original step mismatch", "durable prior stop command differs from the linked plan request", mutateSignedOriginalLink("step_id", "urgent_stop"))
	mutateAndReject("operation fence", func(_ *commandStatePayload, _ *wsproto.CommandPayload, operation *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { operation.Fence++ })
	mutateAndReject("operation identity", func(_ *commandStatePayload, _ *wsproto.CommandPayload, operation *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { operation.OperationID = "other" })
	mutateAndReject("missing operation step", func(_ *commandStatePayload, _ *wsproto.CommandPayload, operation *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { delete(operation.Steps, "victim_stop") })
	mutateAndReject("step fence digest", func(_ *commandStatePayload, _ *wsproto.CommandPayload, _ *ownedStopOperationState, step *ownedStopStepState, _ *[]byte, _ *[]byte) { step.ReceiptSHA256 = strings.Repeat("0", 64) })
	mutateAndReject("missing durable result", func(state *commandStatePayload, _ *wsproto.CommandPayload, _ *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { delete(state.Results, command.ID) })
	mutateAndReject("wrong result node", func(state *commandStatePayload, _ *wsproto.CommandPayload, _ *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { result := state.Results[command.ID]; result.NodeID = "other"; state.Results[command.ID] = result })
	mutateAndReject("pinned root key", func(_ *commandStatePayload, _ *wsproto.CommandPayload, _ *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, public *[]byte) { (*public)[0] ^= 0xff })
	mutateAndReject("prior receipt digest", func(state *commandStatePayload, _ *wsproto.CommandPayload, _ *ownedStopOperationState, _ *ownedStopStepState, _ *[]byte, _ *[]byte) { result := state.Results[command.ID]; result.Result["receipt_sha256"] = strings.Repeat("0", 64); state.Results[command.ID] = result })
	mutateAndRejectExpected("prior receipt signature", "prior stop receipt failed its exact command join", func(state *commandStatePayload, command *wsproto.CommandPayload, operation *ownedStopOperationState, step *ownedStopStepState, raw *[]byte, _ *[]byte) {
		var bad ownedStopReceipt
		_ = json.Unmarshal(*raw, &bad)
		bad.Signature = strings.Repeat("0", 128)
		*raw, _ = json.Marshal(bad)
		digest := sha256Hex(*raw)
		step.ReceiptSHA256 = digest
		command.Args["prior_receipt_sha256"] = digest
		result := state.Results[step.CommandID]
		result.Result["receipt"] = string(*raw)
		result.Result["receipt_sha256"] = digest
		state.Results[step.CommandID] = result
		operation.Steps["victim_stop"] = *step
	})
	mutateAndRejectExpected("original command signature", "durable prior stop command is invalid", func(state *commandStatePayload, command *wsproto.CommandPayload, operation *ownedStopOperationState, step *ownedStopStepState, raw *[]byte, _ *[]byte) {
		result := state.Results[step.CommandID]
		wire, _ := base64.StdEncoding.DecodeString(result.Result["original_envelope"].(string))
		var original wsproto.CommandPayload
		if json.Unmarshal(wire, &original) != nil {
			t.Fatal("decode copied original stop command")
		}
		original.Signature = "invalid-signature"
		wire, _ = wsproto.CanonicalCommandEnvelope(original)
		result.Result["original_envelope"] = base64.StdEncoding.EncodeToString(wire)
		state.Results[step.CommandID] = result
		step.EnvelopeSHA256 = sha256Hex(wire)
		var receipt ownedStopReceipt
		if json.Unmarshal(*raw, &receipt) != nil {
			t.Fatal("decode copied signed receipt")
		}
		receipt.OriginalEnvelopeSHA256 = sha256Hex(wire)
		receipt.Signature = ""
		unsigned, _ := json.Marshal(receipt)
		receipt.Signature = hex.EncodeToString(ed25519.Sign(private, ownedStopReceiptSigningMaterial(unsigned)))
		*raw, _ = json.Marshal(receipt)
		digest := sha256Hex(*raw)
		step.ReceiptSHA256 = digest
		command.Args["prior_receipt_sha256"] = digest
		result = state.Results[step.CommandID]
		result.Result["receipt"] = string(*raw)
		result.Result["receipt_sha256"] = digest
		state.Results[step.CommandID] = result
		operation.Steps["victim_stop"] = *step
	})
	mutateAndReject("noncanonical original command", func(state *commandStatePayload, _ *wsproto.CommandPayload, operation *ownedStopOperationState, step *ownedStopStepState, _ *[]byte, _ *[]byte) {
		result := state.Results[command.ID]
		wire, _ := base64.StdEncoding.DecodeString(result.Result["original_envelope"].(string))
		wire = append(wire, ' ')
		result.Result["original_envelope"] = base64.StdEncoding.EncodeToString(wire)
		state.Results[command.ID] = result
		step.EnvelopeSHA256 = sha256Hex(wire)
		operation.Steps["victim_stop"] = *step
	})
}

func priorStopResult(command wsproto.CommandPayload, wire []byte, public ed25519.PublicKey, receipt []byte) wsproto.CommandResultPayload {
	return wsproto.CommandResultPayload{ID: command.ID, NodeID: command.NodeID, OK: true, Result: map[string]any{
		"action": command.Command, "command_id": command.ID, "idempotency_key": command.IdempotencyKey,
		"original_envelope": base64.StdEncoding.EncodeToString(wire), "pinned_root_public_key": base64.StdEncoding.EncodeToString(public),
		"receipt": string(receipt), "receipt_sha256": sha256Hex(receipt),
	}, CompletedAt: time.Now().UTC()}
}

func mustParsePlanBrokerStoppedState(t *testing.T, raw []byte) checkpointPlanBrokerStoppedState {
	t.Helper()
	observed, err := parseCheckpointPlanBrokerStoppedState(raw)
	if err != nil {
		t.Fatalf("stopped observation control fixture is malformed: %v", err)
	}
	return observed
}

func TestPlanBrokerJobParserUsesExactUnitIdentity(t *testing.T) {
	unit := "vram-plan-relaunch-cpu-0123456789abcdef.service"
	if pending, err := checkpointPlanBrokerPendingJobForUnit([]byte("7 other-vram-plan-relaunch-cpu-0123456789abcdef.service start running\n"), unit); err != nil || pending {
		t.Fatalf("substring-matching unrelated unit was treated as pending: pending=%v err=%v", pending, err)
	}
	if pending, err := checkpointPlanBrokerPendingJobForUnit([]byte("7 "+unit+" start running\n"), unit); err != nil || !pending {
		t.Fatalf("exact unit pending job was missed: pending=%v err=%v", pending, err)
	}
	for _, malformed := range [][]byte{
		[]byte("7 " + unit + " start running"),
		[]byte("job " + unit + " start running\n"),
		[]byte("7 " + unit + " start\n"),
	} {
		if _, err := checkpointPlanBrokerPendingJobForUnit(malformed, unit); err == nil {
			t.Fatalf("malformed systemd job inventory accepted: %q", malformed)
		}
	}
}
