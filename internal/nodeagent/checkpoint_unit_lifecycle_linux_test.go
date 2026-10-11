//go:build linux && owned_stop_systemd_lifetime

package nodeagent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"vram-governor/internal/safefile"
)

const ownedStopLifetimeSystemdRun = "/usr/bin/systemd-run"
const ownedStopLifetimeSystemctl = "/usr/bin/systemctl"
const ownedStopLifetimeNotify = "/usr/bin/systemd-notify"
const ownedStopLifetimeEnv = "VRAM_GOVERNOR_OWNED_STOP_LIFETIME_FIXTURE"

type ownedStopLifetimeChild struct {
	SupervisorPID        int    `json:"supervisor_pid"`
	SupervisorStartTicks uint64 `json:"supervisor_start_ticks"`
	WorkerPID            int    `json:"worker_pid"`
	WorkerStartTicks     uint64 `json:"worker_start_ticks"`
}

// This is the sole opt-in systemd test. Ordinary go test ./... cannot create
// a transient unit or private fixture. It runs as root in the local WSL system
// manager and uses only a uniquely named transient CPU unit.
func TestOwnedStopSystemdLifetimeVerifier(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	observation, err := runOwnedStopLifetimeFixture(ctx, binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCheckpointOwnedStopLifetime(observation); err != nil {
		t.Fatal(err)
	}
}

func runOwnedStopLifetimeFixture(ctx context.Context, testBinary string) (observation checkpointOwnedStopLifetimeObservation, resultErr error) {
	if ctx == nil || ctx.Err() != nil || os.Geteuid() != 0 || !filepath.IsAbs(testBinary) || filepath.Clean(testBinary) != testBinary {
		return observation, errors.New("owned stop lifetime fixture requires a bounded root WSL request")
	}
	release, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil || !(strings.Contains(strings.ToLower(string(release)), "microsoft") || strings.Contains(strings.ToLower(string(release)), "wsl")) {
		return observation, errors.New("owned stop lifetime oracle is restricted to local WSL")
	}
	for _, executable := range []string{ownedStopLifetimeSystemdRun, ownedStopLifetimeSystemctl, ownedStopLifetimeNotify} {
		info, err := os.Stat(executable)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
			return observation, errors.New("local root-systemd lifetime tools are unavailable")
		}
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return observation, err
	}
	unit := "vram-owned-stop-lifetime-" + hex.EncodeToString(nonce[:8]) + ".service"
	if !regexp.MustCompile(`^vram-owned-stop-lifetime-[0-9a-f]{16}\.service$`).MatchString(unit) {
		return observation, errors.New("unique transient lifetime unit name is malformed")
	}
	preflight, err := readOwnedStopLifetimeLoadState(ctx, unit)
	if err != nil || preflight != "not-found" {
		return observation, errors.New("unique transient lifetime unit was not positively absent before creation")
	}
	fixture, err := os.MkdirTemp(os.TempDir(), "vram-owned-stop-lifetime-")
	if err != nil {
		return observation, err
	}
	unitOwned := false
	fixtureInfo, err := os.Lstat(fixture)
	if err != nil || !fixtureInfo.IsDir() || fixtureInfo.Mode()&os.ModeSymlink != 0 || fixtureInfo.Mode().Perm() != 0o700 {
		return observation, errors.New("private lifetime fixture directory has unsafe identity or permissions")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		unitAbsent := !unitOwned
		if unitOwned {
			loadState, queryErr := readOwnedStopLifetimeLoadState(cleanup, unit)
			if queryErr == nil && loadState == "not-found" {
				unitAbsent = true
			} else if queryErr == nil && loadState == "loaded" {
				_, stopErr := runOwnedStopLifetimeCommand(cleanup, ownedStopLifetimeSystemctl, "stop", unit)
				loadState, queryErr = readOwnedStopLifetimeLoadState(cleanup, unit)
				if queryErr == nil && loadState == "loaded" {
					_, resetErr := runOwnedStopLifetimeCommand(cleanup, ownedStopLifetimeSystemctl, "reset-failed", unit)
					loadState, queryErr = readOwnedStopLifetimeLoadState(cleanup, unit)
					if resetErr != nil && queryErr == nil && loadState != "not-found" {
						resultErr = errors.Join(resultErr, fmt.Errorf("reset exact owned unit: %w", resetErr))
					}
				}
				if queryErr == nil && loadState == "not-found" {
					unitAbsent = true
				} else {
					resultErr = errors.Join(resultErr, errors.New("exact transient unit remains present or uncertain after bounded cleanup"))
				}
				if stopErr != nil && !unitAbsent {
					resultErr = errors.Join(resultErr, fmt.Errorf("stop exact owned unit: %w", stopErr))
				}
			} else {
				resultErr = errors.Join(resultErr, errors.New("exact transient unit LoadState is uncertain; fixture preserved"))
			}
		}
		current, statErr := os.Lstat(fixture)
		if unitAbsent && statErr == nil && current.IsDir() && current.Mode()&os.ModeSymlink == 0 && os.SameFile(fixtureInfo, current) && filepath.Dir(fixture) == os.TempDir() && strings.HasPrefix(filepath.Base(fixture), "vram-owned-stop-lifetime-") {
			if removeErr := os.RemoveAll(fixture); removeErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("remove exact private lifetime fixture: %w", removeErr))
			}
		} else if statErr == nil || !errors.Is(statErr, os.ErrNotExist) {
			resultErr = errors.Join(resultErr, errors.New("lifetime fixture identity changed; preserved it"))
		}
	}()
	for _, name := range []string{"worker-stop", "worker-exited", "supervisor.json", "supervisor-exited", "durable-ack"} {
		if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
			return observation, errors.New("invalid private fixture leaf")
		}
	}
	unitOwned = true
	args := []string{"--collect", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=all", "--property=ExitType=cgroup", "--property=KillMode=control-group", "--property=TimeoutStartSec=30s", "--property=TimeoutStopSec=5s", "--quiet", "--", "/usr/bin/env", ownedStopLifetimeEnv + "=supervisor:" + fixture, testBinary, "-test.run=^TestOwnedStopLifetimeHelperProcess$"}
	if _, err := runOwnedStopLifetimeCommand(ctx, ownedStopLifetimeSystemdRun, args...); err != nil {
		return observation, fmt.Errorf("start unique root transient lifetime unit: %w", err)
	}
	child, err := waitOwnedStopLifetimeChild(ctx, filepath.Join(fixture, "supervisor.json"))
	if err != nil {
		return observation, err
	}
	initial, err := readOwnedStopLifetimeUnit(ctx, unit)
	if err != nil || initial["ExitType"] != "cgroup" || initial["MainPID"] != strconv.Itoa(child.WorkerPID) || initial["ActiveState"] != "active" || initial["InvocationID"] == "" {
		return observation, errors.New("transient unit did not bind worker MAINPID under ExitType=cgroup")
	}
	workerTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(child.WorkerPID)), child.WorkerPID)
	if err != nil || workerTicks != child.WorkerStartTicks {
		return observation, errors.New("transient unit worker incarnation changed before stop barrier")
	}
	if err := writeOwnedStopLifetimeMarker(fixture, "worker-stop"); err != nil {
		return observation, err
	}
	if err := waitOwnedStopLifetimePath(ctx, filepath.Join(fixture, "worker-exited")); err != nil {
		return observation, errors.New("worker did not cross the explicit CPU stop-completion barrier")
	}
	active, err := readOwnedStopLifetimeUnit(ctx, unit)
	if err != nil || active["ExitType"] != "cgroup" || active["ActiveState"] != "active" || active["InvocationID"] != initial["InvocationID"] || active["ControlGroup"] != initial["ControlGroup"] {
		return observation, errors.New("supervisor did not keep the same unit cgroup active after worker exit")
	}
	supervisorTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(child.SupervisorPID)), child.SupervisorPID)
	if err != nil || supervisorTicks != child.SupervisorStartTicks {
		return observation, errors.New("fixed supervisor exited or changed incarnation before acknowledgement")
	}
	supervisorCgroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(child.SupervisorPID), "cgroup"), active["ControlGroup"])
	if err != nil || supervisorCgroup != active["ControlGroup"] {
		return observation, errors.New("fixed supervisor left the active worker unit cgroup")
	}
	if err := writeOwnedStopLifetimeMarker(fixture, "durable-ack"); err != nil {
		return observation, err
	}
	if err := waitOwnedStopLifetimePath(ctx, filepath.Join(fixture, "supervisor-exited")); err != nil {
		return observation, errors.New("supervisor did not exit after durable acknowledgement")
	}
	final, err := waitOwnedStopLifetimeInactive(ctx, unit)
	if err != nil {
		return observation, err
	}
	return checkpointOwnedStopLifetimeObservation{ExitType: initial["ExitType"], ActiveState: final["ActiveState"], SubState: final["SubState"], MainPID: child.WorkerPID, ExpectedWorkerPID: child.WorkerPID, ExpectedWorkerTicks: child.WorkerStartTicks, SupervisorPID: child.SupervisorPID, ExpectedSupervisorTicks: child.SupervisorStartTicks, SupervisorInUnit: true, SupervisorAlive: true, WorkerExited: true, DurableAckObserved: true, UnitInactiveAfterAck: final["ActiveState"] == "inactive", ControlGroup: active["ControlGroup"]}, nil
}

func readOwnedStopLifetimeUnit(ctx context.Context, unit string) (map[string]string, error) {
	output, err := runOwnedStopLifetimeCommand(ctx, ownedStopLifetimeSystemctl, "show", unit, "--property=ExitType", "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	if err != nil {
		return nil, err
	}
	values := make(map[string]string, 6)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || value == "" || values[key] != "" {
			return nil, errors.New("transient lifetime unit observation is malformed")
		}
		switch key {
		case "ExitType", "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState":
			values[key] = value
		default:
			return nil, errors.New("transient lifetime unit observation has unknown fields")
		}
	}
	if len(values) != 6 || !validOwnedStopLifetimeCgroup(values["ControlGroup"]) || !checkpointInvocationIDRE.MatchString(strings.ToLower(values["InvocationID"])) {
		return nil, errors.New("transient lifetime unit observation is incomplete")
	}
	return values, nil
}

func waitOwnedStopLifetimeInactive(ctx context.Context, unit string) (map[string]string, error) {
	for {
		loadState, err := readOwnedStopLifetimeLoadState(ctx, unit)
		if err == nil && loadState == "not-found" {
			return map[string]string{"ActiveState": "inactive", "SubState": "dead"}, nil
		}
		if err == nil && loadState == "loaded" {
			observation, observeErr := readOwnedStopLifetimeUnit(ctx, unit)
			if observeErr == nil && observation["ActiveState"] == "inactive" && observation["SubState"] == "dead" {
				return observation, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("unique transient lifetime unit did not become inactive after acknowledgement")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func readOwnedStopLifetimeLoadState(ctx context.Context, unit string) (string, error) {
	if !regexp.MustCompile(`^vram-owned-stop-lifetime-[0-9a-f]{16}\.service$`).MatchString(unit) {
		return "", errors.New("lifetime unit name is not an exact owned fixture name")
	}
	output, err := runOwnedStopLifetimeCommand(ctx, ownedStopLifetimeSystemctl, "show", "--property=LoadState", "--value", unit)
	if err != nil {
		return "", err
	}
	state := strings.TrimSpace(output)
	if state != "loaded" && state != "not-found" {
		return "", errors.New("systemd returned an unknown lifetime unit LoadState")
	}
	return state, nil
}

func waitOwnedStopLifetimeChild(ctx context.Context, path string) (ownedStopLifetimeChild, error) {
	for {
		var child ownedStopLifetimeChild
		if err := readOwnedStopLifetimeChild(path, &child); err == nil && child.SupervisorPID > 1 && child.WorkerPID > 1 && child.SupervisorStartTicks > 0 && child.WorkerStartTicks > 0 {
			return child, nil
		}
		select {
		case <-ctx.Done():
			return ownedStopLifetimeChild{}, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func readOwnedStopLifetimeChild(path string, child *ownedStopLifetimeChild) error {
	if child == nil || filepath.Clean(path) != path || !filepath.IsAbs(path) {
		return errors.New("lifetime child identity path is invalid")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() <= 0 || before.Size() > 512 {
		return errors.New("lifetime child identity file is invalid")
	}
	file, err := safefile.OpenReadOnlyNoFollow(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(before, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 512 {
		return errors.New("lifetime child identity descriptor changed before read")
	}
	body, err := io.ReadAll(io.LimitReader(file, 513))
	after, statErr := file.Stat()
	pathAfter, pathErr := os.Lstat(path)
	if err != nil || int64(len(body)) != info.Size() || statErr != nil || pathErr != nil || !os.SameFile(info, after) || !os.SameFile(info, pathAfter) || pathAfter.Mode()&os.ModeSymlink != 0 || !sameCheckpointFileSnapshot(info, after) {
		return errors.New("lifetime child identity changed during held-descriptor read")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(child); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("lifetime child identity has trailing bytes")
	}
	canonical, err := json.Marshal(*child)
	if err != nil || string(canonical) != string(body) || *child == (ownedStopLifetimeChild{}) {
		return errors.New("lifetime child identity is not canonical or empty")
	}
	return nil
}

func writeOwnedStopLifetimeMarker(fixture, name string) error {
	if filepath.Base(name) != name || name == "" || strings.ContainsAny(name, `/\\`) {
		return errors.New("lifetime fixture marker name is invalid")
	}
	file, err := os.OpenFile(filepath.Join(fixture, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(fixture)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func writeOwnedStopLifetimeChild(fixture, name string, child ownedStopLifetimeChild) error {
	if filepath.Base(name) != name || name == "" || strings.ContainsAny(name, `/\\`) {
		return errors.New("lifetime fixture child path is invalid")
	}
	body, err := json.Marshal(child)
	if err != nil {
		return err
	}
	path := filepath.Join(fixture, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	written, err := file.Write(body)
	if err != nil {
		_ = file.Close()
		return err
	}
	if written != len(body) {
		_ = file.Close()
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(fixture)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func waitOwnedStopLifetimePath(ctx context.Context, path string) error {
	for {
		info, err := os.Lstat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 && info.Size() == 0 {
			return nil
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func runOwnedStopLifetimeCommand(ctx context.Context, executable string, args ...string) (string, error) {
	if ctx == nil || ctx.Err() != nil || (executable != ownedStopLifetimeSystemctl && executable != ownedStopLifetimeSystemdRun && executable != ownedStopLifetimeNotify) {
		return "", errors.New("lifetime command context is unavailable")
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(bounded, executable, args...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	command.WaitDelay = time.Second
	output := &checkpointBoundedOutput{max: 64 * 1024}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	text, outputErr := output.String()
	if outputErr != nil {
		return "", outputErr
	}
	if err != nil {
		return text, fmt.Errorf("bounded local systemd command failed: %w", err)
	}
	return text, nil
}

func TestOwnedStopLifetimeHelperProcess(t *testing.T) {
	role := os.Getenv(ownedStopLifetimeEnv)
	if role == "" {
		return
	}
	parts := strings.SplitN(role, ":", 2)
	if len(parts) != 2 || filepath.Clean(parts[1]) != parts[1] || !filepath.IsAbs(parts[1]) {
		os.Exit(91)
	}
	fixture := parts[1]
	switch parts[0] {
	case "worker":
		pid := os.Getpid()
		ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
		if err != nil {
			os.Exit(92)
		}
		if err := writeOwnedStopLifetimeChild(fixture, "worker.json", ownedStopLifetimeChild{WorkerPID: pid, WorkerStartTicks: ticks}); err != nil {
			os.Exit(93)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		if err := waitOwnedStopLifetimePath(ctx, filepath.Join(fixture, "worker-stop")); err != nil {
			os.Exit(94)
		}
		if err := writeOwnedStopLifetimeMarker(fixture, "worker-exited"); err != nil {
			os.Exit(95)
		}
	case "supervisor":
		pid := os.Getpid()
		ticks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
		if err != nil {
			os.Exit(96)
		}
		binary, err := os.Executable()
		if err != nil {
			os.Exit(97)
		}
		worker := exec.Command(binary, "-test.run=^TestOwnedStopLifetimeHelperProcess$")
		worker.Env = []string{"PATH=/usr/bin:/bin", ownedStopLifetimeEnv + "=worker:" + fixture}
		if err := worker.Start(); err != nil {
			os.Exit(98)
		}
		workerPID := worker.Process.Pid
		workerTicks, err := waitOwnedStopLifetimeWorkerReady(fixture, workerPID)
		if err != nil {
			_ = worker.Process.Kill()
			_ = worker.Wait()
			os.Exit(99)
		}
		if err := writeOwnedStopLifetimeChild(fixture, "supervisor.json", ownedStopLifetimeChild{SupervisorPID: pid, SupervisorStartTicks: ticks, WorkerPID: workerPID, WorkerStartTicks: workerTicks}); err != nil {
			_ = worker.Process.Kill()
			_ = worker.Wait()
			os.Exit(100)
		}
		notify := exec.Command(ownedStopLifetimeNotify, "--pid="+strconv.Itoa(workerPID), "MAINPID="+strconv.Itoa(workerPID), "READY=1")
		if err := notify.Run(); err != nil {
			_ = worker.Process.Kill()
			_ = worker.Wait()
			os.Exit(101)
		}
		if err := worker.Wait(); err != nil {
			os.Exit(102)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := waitOwnedStopLifetimePath(ctx, filepath.Join(fixture, "durable-ack")); err != nil {
			os.Exit(103)
		}
		if err := writeOwnedStopLifetimeMarker(fixture, "supervisor-exited"); err != nil {
			os.Exit(104)
		}
	default:
		os.Exit(105)
	}
}

func waitOwnedStopLifetimeWorkerReady(fixture string, expectedPID int) (uint64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		var child ownedStopLifetimeChild
		if err := readOwnedStopLifetimeChild(filepath.Join(fixture, "worker.json"), &child); err == nil && child.WorkerPID == expectedPID && child.WorkerStartTicks > 0 {
			return child.WorkerStartTicks, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
