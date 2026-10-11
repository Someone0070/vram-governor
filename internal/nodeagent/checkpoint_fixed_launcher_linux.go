//go:build linux

package nodeagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const checkpointFixedSystemctl = "/usr/bin/systemctl"
const checkpointOwnedStopMaxFrame = 64 << 10

var ownedStopEnvCredentialRE = regexp.MustCompile(`^[A-Za-z0-9._~+\-]+$`)

type checkpointFixedLinuxNotify struct{ socket string }

func runCheckpointFixedLauncherPlatform(ctx context.Context) error {
	bounded, cancel := context.WithTimeout(ctx, checkpointFixedStartupTimeout)
	defer cancel()
	plan, err := OpenCheckpointLaunchPlan(bounded, checkpointFixedPlanPath)
	if err != nil {
		return fmt.Errorf("open fixed launch plan: %w", err)
	}
	defer plan.Close()
	spec := plan.Spec()
	if err := validateCheckpointFixedPlan(spec); err != nil {
		return fmt.Errorf("fixed launch plan paths: %w", err)
	}
	if spec.Version != checkpointLaunchPlanVersion2 {
		return errors.New("legacy v1 launch plan cannot start a new managed placement")
	}
	placement, err := refreshCheckpointDevicePlacementPlatform(bounded, spec)
	if err != nil {
		return fmt.Errorf("fresh fixed-plan device discovery: %w", err)
	}
	if err := validateCheckpointPlacementJoin(spec, placement); err != nil {
		return err
	}
	store, err := OpenCheckpointCustodyStore(CheckpointCustodyConfig{Root: spec.Custody.Root, MaxArtifactBytes: spec.Custody.MaxArtifactBytes, MaxStagingBytes: spec.Custody.MaxStagingBytes, ReserveBytes: spec.Custody.ReserveBytes})
	if err != nil {
		return fmt.Errorf("open fixed custody store: %w", err)
	}
	model, err := store.PrepareReusable(bounded, CheckpointCustodySource{Path: spec.Model.Path, ApprovedSHA256: spec.Model.SHA256, ExpectedBytes: spec.Model.Bytes})
	if err != nil {
		return fmt.Errorf("prepare fixed model source: %w", err)
	}
	prepared := true
	defer func() {
		if prepared {
			cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
			discardErr := model.Discard(cleanup)
			stop()
			if discardErr != nil {
				retainCheckpointPreparedModel(model)
			}
		}
	}()
	if err = plan.Recheck(bounded); err != nil {
		return fmt.Errorf("recheck fixed launch plan before begin: %w", err)
	}
	endpoint := net.JoinHostPort(spec.Endpoint.Host, strconv.Itoa(spec.Endpoint.Port))
	cmd, runtimeLog, err := fixedCheckpointPlacementCommand(spec.Executable.Path, spec, placement)
	if err != nil {
		return fmt.Errorf("construct fixed managed placement command: %w", err)
	}
	launch, err := store.beginFixedContext(bounded, model, CheckpointCustodyLaunchRequest{Command: cmd, Endpoint: "http://" + endpoint, ServiceUnit: checkpointIdentityServiceUnit, ActualAlias: spec.Alias, ExpectedExecutableSHA256: spec.Executable.SHA256})
	if err != nil {
		return fmt.Errorf("begin fixed controlled launch: %w", err)
	}
	prepared = false
	if err = plan.Recheck(bounded); err != nil {
		return checkpointFixedAbort(launch, fmt.Errorf("recheck fixed launch plan before start: %w", err))
	}
	if err = launch.Start(); err != nil {
		return checkpointFixedAbort(launch, fmt.Errorf("start fixed controlled child: %w", err))
	}
	notify, err := fixedNotifyFromEnvironment()
	if err != nil {
		return checkpointFixedAbort(launch, err)
	}
	if err = waitFixedListener(bounded, spec.Endpoint.Host, spec.Endpoint.Port); err != nil {
		return checkpointFixedAbort(launch, err)
	}
	pid := launch.cmd.Process.Pid
	var loadingUnit checkpointFixedUnitState
	var loadingChildTicks, loadingSupervisorTicks uint64
	var stopServer *checkpointOwnedStopServer
	steps := checkpointFixedStartupSteps{
		commit: func(stepCtx context.Context) error {
			if err := plan.Recheck(stepCtx); err != nil {
				return fmt.Errorf("recheck pinned launch plan before commit: %w", err)
			}
			var err error
			loadingUnit, err = readCheckpointFixedUnit(stepCtx)
			if err != nil {
				return err
			}
			supervisorPID := os.Getpid()
			if loadingUnit.MainPID != supervisorPID || loadingUnit.Active != "activating" || loadingUnit.Sub == "" || loadingUnit.Sub == "running" || !checkpointInvocationIDRE.MatchString(loadingUnit.Invocation) || loadingUnit.Invocation == strings.Repeat("0", 32) || !validCheckpointCgroupPath(loadingUnit.ControlGroup) {
				return errors.New("pre-commit loading unit does not identify the fixed supervisor")
			}
			loadingChildTicks, err = checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
			if err != nil || loadingChildTicks == 0 {
				return errors.New("fixed loading child incarnation is unavailable")
			}
			loadingSupervisorTicks, err = checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(supervisorPID)), supervisorPID)
			if err != nil || loadingSupervisorTicks == 0 {
				return errors.New("fixed loading supervisor incarnation is unavailable")
			}
			return runCheckpointFixedCommitAfterReadiness(stepCtx, func(checkCtx context.Context) error {
				return waitCheckpointRuntimeReady(checkCtx, spec.Endpoint, func(childCtx context.Context) error {
					return verifyFixedLoadingChildAssociation(childCtx, plan, launch, supervisorPID, loadingChildTicks, loadingSupervisorTicks, loadingUnit)
				})
			}, func(commitCtx context.Context) error {
				if err := plan.Recheck(commitCtx); err != nil {
					return fmt.Errorf("recheck pinned launch plan before custody commit: %w", err)
				}
				if err := launch.Commit(commitCtx); err != nil {
					return err
				}
				state, err := readCheckpointFixedUnit(commitCtx)
				if err != nil {
					return err
				}
				if state != loadingUnit {
					return errors.New("fixed unit invocation changed between loading readiness and custody commit")
				}
				return nil
			})
		},
		mainPID: func(stepCtx context.Context, workerPID int) error {
			return fixedNotifyCall(stepCtx, func(callCtx context.Context) error { return notify.MainPID(callCtx, workerPID) })
		},
		barrier: func(stepCtx context.Context) error { return fixedNotifyCall(stepCtx, notify.Barrier) },
		join: func(stepCtx context.Context) error {
			if err := joinFixedStartupTwice(stepCtx, plan, store, launch, os.Getpid(), runtimeLog); err != nil {
				return err
			}
			var startErr error
			stopServer, startErr = startCheckpointOwnedStopServer(plan, launch)
			return startErr
		},
		ready: func(stepCtx context.Context) error {
			if err := plan.Recheck(stepCtx); err != nil {
				return fmt.Errorf("recheck fixed launch plan before READY: %w", err)
			}
			return fixedNotifyCall(stepCtx, notify.Ready)
		},
	}
	err = runCheckpointFixedStartupSteps(bounded, pid, steps)
	if err != nil {
		if stopServer != nil {
			_ = stopServer.Close()
		}
		return checkpointFixedAbort(launch, fmt.Errorf("fixed startup protocol failed: %w", err))
	}
	return superviseFixedChild(ctx, plan, launch, stopServer)
}

func verifyFixedLoadingChildAssociation(ctx context.Context, plan *PinnedCheckpointLaunchPlan, launch *CheckpointControlledLaunch, supervisorPID int, expectedChildTicks, expectedSupervisorTicks uint64, expectedUnit checkpointFixedUnitState) error {
	if ctx == nil || plan == nil || launch == nil || supervisorPID <= 1 || expectedChildTicks == 0 || expectedSupervisorTicks == 0 || launch.cmd == nil || launch.cmd.Process == nil {
		return errors.New("loading child association is incomplete")
	}
	if err := plan.Recheck(ctx); err != nil {
		return err
	}
	launch.mu.Lock()
	pidfd, started, reaped := launch.pidfd, launch.started, launch.reaped
	launch.mu.Unlock()
	if !started || reaped || pidfd < 0 {
		return errors.New("loading child retained pidfd is unavailable")
	}
	poll := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
	ready, err := unix.Poll(poll, 0)
	if err != nil || ready != 0 || poll[0].Revents != 0 {
		return errors.New("loading child pidfd reports exit or cannot be checked")
	}
	pid := launch.cmd.Process.Pid
	state, err := readCheckpointFixedUnit(ctx)
	if err != nil {
		return err
	}
	if pid <= 1 || state != expectedUnit || state.MainPID != supervisorPID || state.Active != "activating" || state.Sub == "" || state.Sub == "running" || !checkpointInvocationIDRE.MatchString(state.Invocation) || state.Invocation == strings.Repeat("0", 32) || !validCheckpointCgroupPath(state.ControlGroup) {
		return errors.New("loading unit no longer identifies the owned activating child")
	}
	parent, err := fixedProcessParent(ctx, pid)
	if err != nil || parent != supervisorPID {
		return errors.New("loading child is no longer the direct child of the supervisor")
	}
	childTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || childTicks != expectedChildTicks {
		return errors.New("loading child process incarnation changed")
	}
	supervisorTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(supervisorPID)), supervisorPID)
	if err != nil || supervisorTicks != expectedSupervisorTicks {
		return errors.New("loading supervisor process incarnation changed")
	}
	childGroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(pid), "cgroup"), state.ControlGroup)
	if err != nil {
		return err
	}
	supervisorGroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(supervisorPID), "cgroup"), state.ControlGroup)
	if err != nil {
		return err
	}
	if childGroup != state.ControlGroup || supervisorGroup != state.ControlGroup {
		return errors.New("loading child and supervisor left the exact fixed unit cgroup")
	}
	return ctx.Err()
}

func fixedNotifyCall(ctx context.Context, call func(context.Context) error) error {
	if ctx == nil || call == nil {
		return errors.New("fixed notification call is incomplete")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointFixedNotifyTimeout)
	defer cancel()
	return call(bounded)
}

func checkpointFixedAbort(launch *CheckpointControlledLaunch, cause error) error {
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	launch.mu.Lock()
	started := launch.started
	launch.mu.Unlock()
	if !started {
		abortErr := launch.Abort()
		if abortErr == nil {
			abortErr = launch.ReleaseTerminal(cleanup)
		}
		if abortErr != nil {
			retainCheckpointFixedLaunch(launch)
		}
		return errors.Join(cause, abortErr)
	}
	if err := (&checkpointFixedSupervisor{launch: launch}).cancelStarted(cleanup); err != nil {
		retainCheckpointFixedLaunch(launch)
		return errors.Join(cause, fmt.Errorf("owned child reap or terminal release: %w", err))
	}
	return cause
}

func superviseFixedChild(ctx context.Context, plan *PinnedCheckpointLaunchPlan, launch *CheckpointControlledLaunch, stopServer *checkpointOwnedStopServer) error {
	if ctx == nil {
		return errors.New("fixed child supervision context is required")
	}
	if plan == nil {
		return errors.New("fixed launch plan supervision is required")
	}
	lifetime, stopLifetime := context.WithCancel(ctx)
	monitorDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-lifetime.Done():
				monitorDone <- nil
				return
			case <-ticker.C:
				checkCtx, cancel := context.WithTimeout(lifetime, 3*time.Second)
				err := plan.Recheck(checkCtx)
				cancel()
				if err != nil {
					monitorDone <- fmt.Errorf("pinned plan identity changed during active service lifetime: %w", err)
					stopLifetime()
					return
				}
			}
		}
	}()
	waitDone := make(chan struct{})
	waitResult := error(nil)
	if stopServer != nil {
		stopServer.mu.Lock()
		stopServer.waitDone = waitDone
		stopServer.waitErr = &waitResult
		stopServer.waiterReady = true
		stopServer.mu.Unlock()
		go stopServer.serve()
	}
	go func() {
		waitResult = launch.WaitContext(lifetime)
		close(waitDone)
	}()
	<-waitDone
	err := waitResult
	if stopServer != nil && stopServer.isActive() {
		select {
		case <-stopServer.ackDone:
		case <-lifetime.Done():
			return fmt.Errorf("owned stop acknowledgement did not settle; custody retained: %w", lifetime.Err())
		}
		stopLifetime()
		_ = stopServer.Close()
		if !ownedStopWaitResultAfterDurableAck(err, stopServer.ackErr) {
			return errors.Join(err, stopServer.ackErr)
		}
		return nil
	}
	stopLifetime()
	err = errors.Join(err, <-monitorDone)
	if err != nil {
		launch.mu.Lock()
		reaped := launch.reaped
		launch.mu.Unlock()
		if !reaped {
			retainCheckpointFixedLaunch(launch)
			return fmt.Errorf("fixed child lifetime ended without confirmed reap: %w", err)
		}
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if releaseErr := launch.ReleaseTerminal(cleanup); releaseErr != nil {
		retainCheckpointFixedLaunch(launch)
		return errors.Join(err, fmt.Errorf("release settled fixed launch: %w", releaseErr))
	}
	if stopServer != nil {
		_ = stopServer.Close()
	}
	return err
}

func waitFixedListener(ctx context.Context, host string, port int) error {
	if ctx == nil {
		return errors.New("listener wait context is required")
	}
	deadline := time.NewTimer(checkpointFixedListenerTimeout)
	defer deadline.Stop()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", address)
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-deadline.C:
			timer.Stop()
			return errors.New("fixed child listener did not become ready within bound")
		case <-timer.C:
		}
	}
}

func fixedNotifyFromEnvironment() (*checkpointFixedLinuxNotify, error) {
	value := os.Getenv("NOTIFY_SOCKET")
	if value == "" || len(value) > 107 || strings.ContainsAny(value, "\x00\r\n") {
		return nil, errors.New("systemd notification socket is unavailable or malformed")
	}
	if value[0] == '@' {
		return &checkpointFixedLinuxNotify{socket: "\x00" + value[1:]}, nil
	}
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return nil, errors.New("systemd notification socket path is not canonical")
	}
	return &checkpointFixedLinuxNotify{socket: value}, nil
}

func (n *checkpointFixedLinuxNotify) send(ctx context.Context, message string, passedFD int) error {
	if n == nil || ctx == nil || n.socket == "" || message == "" || strings.ContainsAny(message, "\x00\r\n") {
		return errors.New("systemd notification request is invalid")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	socketFD, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(socketFD)
	deadline := time.Now().Add(checkpointFixedNotifyTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	for {
		err = unix.Connect(socketFD, &unix.SockaddrUnix{Name: n.socket})
		if err == nil || err == unix.EISCONN {
			break
		}
		if err != unix.EINTR && err != unix.EINPROGRESS && err != unix.EALREADY && err != unix.EAGAIN && err != unix.EWOULDBLOCK {
			return err
		}
		if err := waitCheckpointNotifyWritable(ctx, socketFD, deadline); err != nil {
			return err
		}
		if err != unix.EINTR {
			socketErr, sockErr := unix.GetsockoptInt(socketFD, unix.SOL_SOCKET, unix.SO_ERROR)
			if sockErr != nil {
				return sockErr
			}
			if socketErr != 0 {
				return unix.Errno(socketErr)
			}
			break
		}
	}
	var oob []byte
	if passedFD >= 0 {
		oob = unix.UnixRights(passedFD)
	}
	data := []byte(message)
	// The notification socket descriptor and the optional transferred writer
	// are distinct; the latter is supplied by callers.
	for {
		written, sendErr := unix.SendmsgN(socketFD, data, oob, nil, 0)
		if sendErr == nil {
			if written != len(data) {
				return errors.New("systemd notification was not sent completely")
			}
			return ctx.Err()
		}
		if sendErr != unix.EINTR && sendErr != unix.EAGAIN && sendErr != unix.EWOULDBLOCK {
			return sendErr
		}
		if err := waitCheckpointNotifyWritable(ctx, socketFD, deadline); err != nil {
			return err
		}
	}
}

func waitCheckpointNotifyWritable(ctx context.Context, fd int, deadline time.Time) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return context.DeadlineExceeded
		}
		wait := remaining
		if wait > 50*time.Millisecond {
			wait = 50 * time.Millisecond
		}
		events := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		ms := int((wait + time.Millisecond - 1) / time.Millisecond)
		ready, err := unix.Poll(events, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 0 {
			continue
		}
		if events[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return errors.New("systemd notification socket is not writable")
		}
		if events[0].Revents&unix.POLLOUT != 0 {
			return nil
		}
	}
}
func (n *checkpointFixedLinuxNotify) MainPID(ctx context.Context, pid int) error {
	if pid <= 1 {
		return errors.New("systemd MainPID value is invalid")
	}
	return n.send(ctx, "MAINPID="+strconv.Itoa(pid), -1)
}
func (n *checkpointFixedLinuxNotify) Ready(ctx context.Context) error {
	return n.send(ctx, "READY=1", -1)
}
func (n *checkpointFixedLinuxNotify) Barrier(ctx context.Context) error {
	if ctx == nil {
		return errors.New("systemd barrier context is required")
	}
	pipe := []int{-1, -1}
	if err := unix.Pipe2(pipe, unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return err
	}
	defer unix.Close(pipe[0])
	defer func() {
		if pipe[1] >= 0 {
			_ = unix.Close(pipe[1])
		}
	}()
	if err := n.send(ctx, "BARRIER=1", pipe[1]); err != nil {
		return err
	}
	_ = unix.Close(pipe[1])
	pipe[1] = -1
	deadline := time.NewTimer(checkpointFixedNotifyTimeout)
	defer deadline.Stop()
	for {
		var p unix.PollFd
		p.Fd = int32(pipe[0])
		p.Events = unix.POLLIN | unix.POLLHUP
		r, err := unix.Poll([]unix.PollFd{p}, 50)
		if err != nil && err != unix.EINTR {
			return err
		}
		if r > 0 {
			buf := make([]byte, 1)
			nread, readErr := unix.Read(pipe[0], buf)
			if nread == 0 && readErr == nil {
				return ctx.Err()
			}
			if readErr == unix.EAGAIN {
				continue
			}
			if readErr != nil {
				return readErr
			}
			return errors.New("systemd notification barrier returned unexpected data")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("systemd notification barrier exceeded its bound")
		default:
		}
	}
}

func parseCheckpointFixedUnit(raw []byte) (checkpointFixedUnitState, error) {
	if len(raw) == 0 || len(raw) > checkpointUnitMaxOutput {
		return checkpointFixedUnitState{}, errors.New("fixed unit output is empty or oversized")
	}
	values := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" || strings.Count(line, "=") != 1 {
			return checkpointFixedUnitState{}, errors.New("fixed unit output is malformed")
		}
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "MainPID", "InvocationID", "ControlGroup", "ActiveState", "SubState":
		default:
			return checkpointFixedUnitState{}, errors.New("fixed unit output has unexpected property")
		}
		if _, ok := values[key]; ok || value == "" {
			return checkpointFixedUnitState{}, errors.New("fixed unit output has duplicate or empty property")
		}
		values[key] = value
	}
	if len(values) != 5 {
		return checkpointFixedUnitState{}, errors.New("fixed unit output is missing a property")
	}
	pid, err := strconv.Atoi(values["MainPID"])
	state, errState := parseCheckpointUnitProperties([]byte("MainPID=" + values["MainPID"] + "\nInvocationID=" + values["InvocationID"] + "\nControlGroup=" + values["ControlGroup"] + "\nActiveState=active\nSubState=running\n"))
	if err != nil || errState != nil || pid != state.MainPID {
		return checkpointFixedUnitState{}, errors.New("fixed unit process identity is invalid")
	}
	if values["ActiveState"] != "activating" || values["SubState"] == "running" {
		return checkpointFixedUnitState{}, errors.New("fixed service is not in its private activating startup state")
	}
	return checkpointFixedUnitState{MainPID: pid, Invocation: strings.ToLower(values["InvocationID"]), ControlGroup: values["ControlGroup"], Active: values["ActiveState"], Sub: values["SubState"]}, nil
}

func readCheckpointFixedUnit(ctx context.Context) (checkpointFixedUnitState, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, checkpointFixedSystemctl, "show", checkpointIdentityServiceUnit, "--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	cmd.WaitDelay = time.Second
	b := &checkpointUnitOutput{max: checkpointUnitMaxOutput}
	cmd.Stdout, cmd.Stderr = b, b
	if err := cmd.Run(); err != nil {
		return checkpointFixedUnitState{}, fmt.Errorf("read fixed unit manager state: %w", err)
	}
	return parseCheckpointFixedUnit(b.Bytes())
}

func fixedProcessParent(ctx context.Context, pid int) (int, error) {
	if pid <= 1 {
		return 0, errors.New("fixed process PID is invalid")
	}
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	defer file.Close()
	reader := bufio.NewReader(io.LimitReader(file, 16<<10))
	found := 0
	for {
		line, e := reader.ReadString('\n')
		if len(line) > 4096 {
			return 0, errors.New("process status line exceeded bound")
		}
		if strings.HasPrefix(line, "PPid:") {
			if found != 0 {
				return 0, errors.New("duplicate process parent property")
			}
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			parent, pe := strconv.Atoi(value)
			if pe != nil || parent <= 0 {
				return 0, errors.New("process parent is malformed")
			}
			found = parent
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return 0, e
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
	}
	if found == 0 {
		return 0, errors.New("process parent property is missing")
	}
	return found, nil
}

func joinFixedStartupTwice(ctx context.Context, plan *PinnedCheckpointLaunchPlan, store *CheckpointCustodyStore, launch *CheckpointControlledLaunch, supervisorPID int, runtimeLog *checkpointRuntimeLog) error {
	if ctx == nil || plan == nil || store == nil || launch == nil || supervisorPID <= 1 || runtimeLog == nil {
		return errors.New("fixed startup join request is incomplete")
	}
	var previous checkpointFixedUnitState
	var previousBinding CheckpointCustodyVerification
	var previousIdentity CheckpointLocalIdentity
	var samples [2]checkpointFixedStartupSample
	for sample := 0; sample < 2; sample++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := plan.Recheck(ctx); err != nil {
			return err
		}
		placement, err := refreshCheckpointDevicePlacementPlatform(ctx, plan.Spec())
		if err != nil {
			return fmt.Errorf("refresh device association before READY: %w", err)
		}
		if err := validateCheckpointPlacementJoin(plan.Spec(), placement); err != nil {
			return err
		}
		state, err := readCheckpointFixedUnit(ctx)
		if err != nil {
			return err
		}
		pid := launch.cmd.Process.Pid
		if state.MainPID != pid {
			return errors.New("unit MainPID does not equal the owned fixed child")
		}
		binding, ok, err := store.VerifyBinding(ctx, "http://"+net.JoinHostPort(plan.Spec().Endpoint.Host, strconv.Itoa(plan.Spec().Endpoint.Port)), checkpointIdentityServiceUnit)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("authenticated fixed child receipt is absent")
		}
		spec := plan.Spec()
		if binding.PID != pid || binding.ActualAlias != spec.Alias || !strings.EqualFold(binding.ArtifactSHA256, spec.Model.SHA256) || binding.ArtifactSize != spec.Model.Bytes || !strings.EqualFold(binding.ExecutableSHA256, spec.Executable.SHA256) || binding.ExecutablePath != launch.executablePath || binding.Endpoint != "http://"+net.JoinHostPort(spec.Endpoint.Host, strconv.Itoa(spec.Endpoint.Port)) || binding.UnitAssociation != "label-only-unverified" {
			return errors.New("fixed child receipt does not match the pinned launch plan")
		}
		parent, err := fixedProcessParent(ctx, pid)
		if err != nil || parent != supervisorPID {
			return errors.New("fixed child is not a direct child of the live supervisor")
		}
		supervisorStartTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(supervisorPID)), supervisorPID)
		if err != nil || supervisorStartTicks == 0 {
			return errors.New("fixed supervisor process incarnation is unavailable")
		}
		childGroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(pid), "cgroup"), state.ControlGroup)
		if err != nil {
			return err
		}
		supervisorGroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(supervisorPID), "cgroup"), state.ControlGroup)
		if err != nil {
			return err
		}
		if childGroup != state.ControlGroup || supervisorGroup != state.ControlGroup {
			return errors.New("fixed supervisor and worker are not members of the exact unit cgroup")
		}
		childStartTicks, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
		if err != nil || childStartTicks == 0 {
			return errors.New("fixed child process incarnation is unavailable for device attribution")
		}
		footprint, err := observeCheckpointChildPlacement(ctx, plan.Spec(), pid, childStartTicks, runtimeLog)
		if err != nil {
			return fmt.Errorf("fresh child GPU/host/offload verification: %w", err)
		}
		identityReq := CheckpointIdentityRequest{Endpoint: binding.Endpoint, ServiceUnit: checkpointIdentityServiceUnit, ModelPath: binding.ArtifactPath, ExpectedModelSHA256: spec.Model.SHA256, ApprovedModelRoots: []string{filepath.Dir(binding.ArtifactPath)}, ExpectedExecutableSHA256: spec.Executable.SHA256}
		_, host, port, err := parseCheckpointIdentityEndpoint(binding.Endpoint)
		if err != nil {
			return err
		}
		identitySource := checkpointLinuxSource{procRoot: "/proc", mainPID: func(context.Context, string) (int, error) { return pid, nil }}
		identity, err := observeCheckpointIdentityControlledLinux(ctx, identityReq, binding.Endpoint, host, port, identitySource, binding)
		if err != nil {
			return err
		}
		if identity.EvidenceKind != binding.EvidenceKind || identity.PID != pid || identity.BootID != binding.BootID || identity.ProcessStartTicks != binding.ProcessStartTicks || identity.ListenerSocketInode != binding.ListenerSocketInode || identity.ExecutablePath != binding.ExecutablePath || !strings.EqualFold(identity.ExecutableSHA256, binding.ExecutableSHA256) || identity.ModelPath != binding.ArtifactPath || identity.ModelDevice != binding.ArtifactDevice || identity.ModelInode != binding.ArtifactInode || identity.ModelSize != binding.ArtifactSize || !strings.EqualFold(identity.ModelSHA256, binding.ArtifactSHA256) {
			return errors.New("fresh fixed process identity differs from the authenticated receipt")
		}
		finalState, err := readCheckpointFixedUnit(ctx)
		if err != nil {
			return err
		}
		finalBinding, finalOK, err := store.VerifyBinding(ctx, binding.Endpoint, checkpointIdentityServiceUnit)
		if err != nil {
			return err
		}
		if !finalOK || finalBinding != binding || finalState != state {
			return errors.New("fixed unit or authenticated receipt changed during one startup join")
		}
		if err := verifyCheckpointRuntimeHealth(ctx, spec.Endpoint); err != nil {
			return err
		}
		if sample == 1 && (state != previous || binding != previousBinding || identity != previousIdentity) {
			return errors.New("fixed startup identity changed between fresh joins")
		}
		samples[sample] = checkpointFixedStartupSample{unit: state, binding: binding, identity: identity, placement: placement, footprint: footprint, childParent: parent, supervisorStartTicks: supervisorStartTicks, childCgroup: childGroup, supervisorCgroup: supervisorGroup}
		previous, previousBinding, previousIdentity = state, binding, identity
		if sample == 0 {
			timer := time.NewTimer(50 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return validateCheckpointFixedStartupPair(samples[0], samples[1], plan.Spec(), launch.executablePath, launch.cmd.Process.Pid, supervisorPID)
}

var _ checkpointFixedNotify = (*checkpointFixedLinuxNotify)(nil)
