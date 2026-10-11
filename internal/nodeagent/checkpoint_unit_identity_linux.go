//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const checkpointSystemctlPath = "/usr/bin/systemctl"

type checkpointUnitLinuxSource struct {
	procRoot      string
	collect       func(context.Context, int) (checkpointUnitObservation, error)
	verifyCustody func(context.Context, *CheckpointCustodyStore, string, string) (CheckpointCustodyVerification, bool, error)
	observeLocal  func(context.Context, CheckpointIdentityRequest, string, net.IP, uint16, checkpointLinuxSource) (CheckpointLocalIdentity, error)
}

func observeCheckpointManagedUnitPlatform(ctx context.Context, req CheckpointUnitIdentityRequest) (CheckpointVerifiedUnitAssociation, error) {
	return observeCheckpointManagedUnitLinux(ctx, req, checkpointUnitLinuxSource{procRoot: "/proc", collect: collectCheckpointUnitObservation})
}

func observeCheckpointManagedUnitLinux(ctx context.Context, req CheckpointUnitIdentityRequest, source checkpointUnitLinuxSource) (CheckpointVerifiedUnitAssociation, error) {
	if ctx == nil {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit identity context is required")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if req.Custody == nil {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit identity custody store is required")
	}
	if source.procRoot == "" || source.collect == nil {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit observation source is incomplete")
	}
	endpoint, host, port, err := parseCheckpointIdentityEndpoint(req.Identity.Endpoint)
	if err != nil || req.Identity.ServiceUnit != checkpointIdentityServiceUnit {
		return CheckpointVerifiedUnitAssociation{}, errors.New("checkpoint unit identity endpoint or unit is invalid")
	}
	first, err := source.collect(ctx, 0)
	if err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	verify := source.verifyCustody
	if verify == nil {
		verify = func(callCtx context.Context, custody *CheckpointCustodyStore, callEndpoint, unit string) (CheckpointCustodyVerification, bool, error) {
			return custody.VerifyBinding(callCtx, callEndpoint, unit)
		}
	}
	binding, ok, err := verify(ctx, req.Custody, endpoint, checkpointIdentityServiceUnit)
	if err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if !ok {
		return CheckpointVerifiedUnitAssociation{}, errors.New("no authenticated live checkpoint custody binding was found")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	identitySource := checkpointLinuxSource{
		procRoot: source.procRoot,
		mainPID: func(callCtx context.Context, unit string) (int, error) {
			if unit != checkpointIdentityServiceUnit {
				return 0, errors.New("checkpoint identity unit is not allowlisted")
			}
			state, collectErr := source.collect(callCtx, 0)
			if collectErr != nil {
				return 0, collectErr
			}
			return state.MainPID, nil
		},
	}
	observeLocal := source.observeLocal
	var identity CheckpointLocalIdentity
	if observeLocal == nil {
		if binding.EvidenceKind == "controlled-source-fs-verity-v2" {
			identity, err = observeCheckpointIdentityControlledLinux(ctx, req.Identity, endpoint, host, port, identitySource, binding)
		} else {
			identity, err = observeCheckpointIdentityLinux(ctx, req.Identity, endpoint, host, port, identitySource)
		}
	} else {
		identity, err = observeLocal(ctx, req.Identity, endpoint, host, port, identitySource)
	}
	if err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	second, err := source.collect(ctx, identity.PID)
	if err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	finalBinding, finalOK, err := verify(ctx, req.Custody, endpoint, checkpointIdentityServiceUnit)
	if err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	if !finalOK || finalBinding != binding {
		return CheckpointVerifiedUnitAssociation{}, errors.New("authenticated checkpoint custody binding changed during managed-unit observation")
	}
	if err := ctx.Err(); err != nil {
		return CheckpointVerifiedUnitAssociation{}, err
	}
	return joinCheckpointUnitIdentity(binding, identity, req.ExpectedAlias, first, second)
}

func collectCheckpointUnitObservation(ctx context.Context, expectedPID int) (checkpointUnitObservation, error) {
	state, err := checkpointReadSystemdUnitState(ctx)
	if err != nil {
		return checkpointUnitObservation{}, err
	}
	if expectedPID > 0 && state.MainPID != expectedPID {
		return checkpointUnitObservation{}, errors.New("systemd MainPID changed between fresh samples")
	}
	cgroup, err := readCheckpointCgroupMembership(ctx, filepath.Join("/proc", strconv.Itoa(state.MainPID), "cgroup"), state.ControlGroup)
	if err != nil {
		return checkpointUnitObservation{}, err
	}
	return checkpointUnitObservation{
		MainPID: state.MainPID, InvocationID: state.InvocationID, ControlGroup: state.ControlGroup,
		ActiveState: state.ActiveState, SubState: state.SubState, CgroupMembers: cgroup,
	}, nil
}

func checkpointReadSystemdUnitState(ctx context.Context) (checkpointUnitState, error) {
	if ctx == nil {
		return checkpointUnitState{}, errors.New("systemd unit context is required")
	}
	cmdCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, checkpointSystemctlPath, "show", checkpointIdentityServiceUnit,
		"--property=MainPID", "--property=InvocationID", "--property=ControlGroup", "--property=ActiveState", "--property=SubState")
	cmd.WaitDelay = time.Second
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=cat"}
	bounded := &checkpointUnitOutput{max: checkpointUnitMaxOutput}
	cmd.Stdout, cmd.Stderr = bounded, bounded
	if err := cmd.Run(); err != nil {
		return checkpointUnitState{}, fmt.Errorf("read fixed systemd unit state: %w", err)
	}
	return parseCheckpointUnitProperties(bounded.Bytes())
}

type checkpointUnitOutput struct {
	mu   sync.Mutex
	data []byte
	max  int
}

func (b *checkpointUnitOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data)+len(p) > b.max {
		return 0, errors.New("systemd output exceeded its byte bound")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *checkpointUnitOutput) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...)
}

func readCheckpointCgroupMembership(ctx context.Context, filePath, expected string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fd, err := unix.Open(filePath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", fmt.Errorf("open process cgroup membership: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || (stat.Mode&unix.S_IFMT) != unix.S_IFREG {
		_ = unix.Close(fd)
		return "", errors.New("process cgroup membership is not a regular proc file")
	}
	file := os.NewFile(uintptr(fd), filePath)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("process cgroup file handle is unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, checkpointUnitMaxCgroupBytes+1))
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(raw) > checkpointUnitMaxCgroupBytes {
		return "", errors.New("process cgroup membership exceeded its byte bound")
	}
	return parseCheckpointCgroupMembership(raw, expected)
}
