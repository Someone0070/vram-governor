//go:build linux

package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type checkpointManagedObservationSource struct {
	openPlan        func(context.Context) (*PinnedCheckpointLaunchPlan, error)
	validatePlan    func(*PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error)
	recheckPlan     func(context.Context, *PinnedCheckpointLaunchPlan) error
	openStore       func(CheckpointLaunchPlan) (*CheckpointCustodyStore, error)
	associate       func(context.Context, *CheckpointCustodyStore, CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error)
	alias           func(context.Context, CheckpointLaunchEndpoint, string) (string, error)
	placement       func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error)
	namespaceRoute  func(context.Context, int) (bool, error)
	nestedFootprint func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (int64, int64, error)
	footprint       func(context.Context, int, uint64, CheckpointDevicePlacement) (int64, int64, error)
	readArgv        func(int) ([]string, error)
}

func observeCheckpointManagedBindingPlatform(ctx context.Context) (CheckpointManagedBinding, error) {
	return routeCheckpointManagedBindingObserver(ctx, os.Geteuid(), func(callCtx context.Context) (CheckpointManagedBinding, error) {
		local, err := ObserveCheckpointLocalAssociation(callCtx)
		if err != nil {
			return CheckpointManagedBinding{}, err
		}
		return local.Binding, nil
	}, func(callCtx context.Context) (CheckpointManagedBinding, error) {
		return observeCheckpointManagedBindingLinux(callCtx, checkpointManagedObservationSource{
		openPlan: func(callCtx context.Context) (*PinnedCheckpointLaunchPlan, error) {
			return OpenCheckpointLaunchPlan(callCtx, checkpointFixedPlanPath)
		},
		openStore: openCheckpointCustodyStoreReadOnly,
		associate: func(callCtx context.Context, store *CheckpointCustodyStore, plan CheckpointLaunchPlan) (CheckpointVerifiedUnitAssociation, error) {
			endpoint := managedCheckpointEndpoint(plan)
			binding, ok, err := store.VerifyBinding(callCtx, endpoint, checkpointIdentityServiceUnit)
			if err != nil {
				return CheckpointVerifiedUnitAssociation{}, err
			}
			if !ok {
				return CheckpointVerifiedUnitAssociation{}, errors.New("authenticated staged source receipt is absent")
			}
			if err := validateManagedCheckpointReceipt(binding, plan, endpoint); err != nil {
				return CheckpointVerifiedUnitAssociation{}, err
			}
			modelRoot := filepath.Dir(binding.ArtifactPath)
			req := CheckpointUnitIdentityRequest{
				Custody: store,
				Identity: CheckpointIdentityRequest{
					Endpoint: endpoint, ServiceUnit: checkpointIdentityServiceUnit,
					ModelPath: binding.ArtifactPath, ExpectedModelSHA256: plan.Model.SHA256,
					ApprovedModelRoots: []string{modelRoot}, ExpectedExecutableSHA256: plan.Executable.SHA256,
				},
				ExpectedAlias: plan.Alias,
			}
			return ObserveCheckpointManagedUnit(callCtx, req)
		},
		alias: observeCheckpointManagedAlias,
		placement: func(callCtx context.Context, plan CheckpointLaunchPlan) (CheckpointDevicePlacement, error) {
			return refreshCheckpointDevicePlacementPlatform(callCtx, plan)
		},
		namespaceRoute:  checkpointWorkerUsesNestedPIDNamespace,
		nestedFootprint: observeNestedManagedCheckpointFootprint,
		footprint:       observeManagedCheckpointFootprint,
		readArgv:        readManagedCheckpointArgv,
		})
	})
}

func routeCheckpointManagedBindingObserver(ctx context.Context, euid int, localObserver func(context.Context) (CheckpointManagedBinding, error), rootCollector func(context.Context) (CheckpointManagedBinding, error)) (CheckpointManagedBinding, error) {
	if ctx == nil {
		return CheckpointManagedBinding{}, errors.New("managed binding observer context is required")
	}
	if euid != 0 {
		if localObserver == nil {
			return CheckpointManagedBinding{}, errors.New("fixed signed local observer is unavailable")
		}
		binding, err := localObserver(ctx)
		if err != nil {
			return CheckpointManagedBinding{}, err
		}
		return binding, nil
	}
	if rootCollector == nil {
		return CheckpointManagedBinding{}, errors.New("fixed root managed collector is unavailable")
	}
	return rootCollector(ctx)
}

func observeCheckpointManagedBindingLinux(ctx context.Context, source checkpointManagedObservationSource) (CheckpointManagedBinding, error) {
	if ctx == nil || source.openPlan == nil || source.openStore == nil || source.associate == nil || source.alias == nil || source.placement == nil || source.namespaceRoute == nil || source.footprint == nil || source.readArgv == nil {
		return CheckpointManagedBinding{}, errors.New("managed binding observation source is incomplete")
	}
	bounded, cancel := context.WithTimeout(ctx, checkpointManagedBindingTimeout)
	defer cancel()
	planPin, err := source.openPlan(bounded)
	if err != nil {
		return CheckpointManagedBinding{}, fmt.Errorf("pin fixed managed plan: %w", err)
	}
	defer planPin.Close()
	validatePlan := source.validatePlan
	if validatePlan == nil {
		validatePlan = validateManagedCheckpointPlan
	}
	plan, err := validatePlan(planPin)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	recheckPlan := source.recheckPlan
	if recheckPlan == nil {
		recheckPlan = func(callCtx context.Context, pinned *PinnedCheckpointLaunchPlan) error {
			return pinned.Recheck(callCtx)
		}
	}
	if err := recheckPlan(bounded, planPin); err != nil {
		return CheckpointManagedBinding{}, fmt.Errorf("fixed managed plan changed before observation: %w", err)
	}
	store, err := source.openStore(plan)
	if err != nil {
		return CheckpointManagedBinding{}, fmt.Errorf("open existing custody state read-only: %w", err)
	}
	first, err := source.associate(bounded, store, plan)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	if err := validateManagedCheckpointAssociation(first, plan); err != nil {
		return CheckpointManagedBinding{}, err
	}
	argv, err := source.readArgv(first.Identity.PID)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	expectedArgv, err := managedCheckpointExpectedArgv(plan)
	if err != nil || !equalCheckpointArgv(argv, expectedArgv) {
		return CheckpointManagedBinding{}, errors.New("current managed child argv does not exactly match the fixed v2 plan")
	}
	aliasFirst, err := source.alias(bounded, plan.Endpoint, plan.Alias)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	if aliasFirst != plan.Alias {
		return CheckpointManagedBinding{}, errors.New("current backend alias differs from the pinned plan")
	}
	placement, err := source.placement(bounded, plan)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	if err := validateCheckpointPlacementJoin(plan, placement); err != nil {
		return CheckpointManagedBinding{}, err
	}
	nested, err := source.namespaceRoute(bounded, first.Identity.PID)
	if err != nil {
		return CheckpointManagedBinding{}, fmt.Errorf("managed process namespace route is unverified: %w", err)
	}
	var gpuBytes, rssBytes int64
	if nested {
		if source.nestedFootprint == nil {
			return CheckpointManagedBinding{}, errors.New("nested host GPU observer is unavailable")
		}
		gpuBytes, rssBytes, err = source.nestedFootprint(bounded, first.Identity.PID, first.Identity.ProcessStartTicks, plan, placement)
	} else {
		gpuBytes, rssBytes, err = source.footprint(bounded, first.Identity.PID, first.Identity.ProcessStartTicks, placement)
	}
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	if gpuBytes < plan.Placement.MinGPUBytes || rssBytes <= 0 || rssBytes > plan.Placement.MaxHostRSSBytes {
		return CheckpointManagedBinding{}, errors.New("current managed process footprint is outside fixed plan bounds")
	}
	aliasSecond, err := source.alias(bounded, plan.Endpoint, plan.Alias)
	if err != nil || aliasFirst != plan.Alias || aliasSecond != plan.Alias || aliasFirst != aliasSecond {
		return CheckpointManagedBinding{}, errors.New("current backend alias changed or became unavailable during observation")
	}
	second, err := source.associate(bounded, store, plan)
	if err != nil {
		return CheckpointManagedBinding{}, err
	}
	if err := validateManagedCheckpointAssociation(second, plan); err != nil || !sameManagedCheckpointAssociation(first, second) {
		return CheckpointManagedBinding{}, errors.New("managed process, receipt, unit, or listener association changed during observation")
	}
	argvAfter, err := source.readArgv(second.Identity.PID)
	if err != nil || !equalCheckpointArgv(argvAfter, expectedArgv) || !equalCheckpointArgv(argvAfter, argv) {
		return CheckpointManagedBinding{}, errors.New("current managed child argv changed during observation")
	}
	if err := recheckPlan(bounded, planPin); err != nil {
		return CheckpointManagedBinding{}, fmt.Errorf("fixed managed plan changed during observation: %w", err)
	}
	if err := bounded.Err(); err != nil {
		return CheckpointManagedBinding{}, err
	}
	incarnation := managedCheckpointCurrentIncarnation(first, plan, argv)
	return CheckpointManagedBinding{
		Version: checkpointLaunchPlanVersion2, CurrentIncarnation: incarnation,
		PlanSHA256: hexDigest(planPin.contentSHA256[:]), CustodyBindingSHA256: first.Custody.BindingSHA256,
		Alias: aliasFirst, Association: first, Placement: placement,
		GPUBytes: gpuBytes, HostRSSBytes: rssBytes, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}

func hexDigest(raw []byte) string { return fmt.Sprintf("%x", raw) }

func validateManagedCheckpointAssociation(association CheckpointVerifiedUnitAssociation, plan CheckpointLaunchPlan) error {
	if association.Identity.PID <= 1 || association.Invocation == "" || association.ControlGroup == "" || association.Identity.ProcessStartTicks == 0 || association.Identity.ListenerSocketInode == 0 {
		return errors.New("current managed worker association is incomplete")
	}
	identity, receipt := association.Identity, association.Custody
	endpoint := managedCheckpointEndpoint(plan)
	if identity.Endpoint != endpoint || identity.ServiceUnit != checkpointIdentityServiceUnit || identity.ListenerIP != plan.Endpoint.Host || int(identity.ListenerPort) != plan.Endpoint.Port ||
		receipt.Endpoint != endpoint || receipt.ServiceUnit != checkpointIdentityServiceUnit || receipt.BootID != identity.BootID ||
		receipt.PID != identity.PID || receipt.ProcessStartTicks != identity.ProcessStartTicks || receipt.ListenerSocketInode != identity.ListenerSocketInode ||
		receipt.ExecutablePath != identity.ExecutablePath || !strings.EqualFold(receipt.ExecutableSHA256, identity.ExecutableSHA256) {
		return errors.New("current worker identity does not join the authenticated receipt and fixed listener")
	}
	if err := validateManagedCheckpointReceipt(receipt, plan, endpoint); err != nil {
		return err
	}
	if association.Custody.EvidenceKind != "controlled-source-fs-verity-v2" || association.Custody.ModelArgument != "/proc/self/fd/4" || association.Custody.ActualAlias != plan.Alias || association.Identity.ModelPath != association.Custody.ArtifactPath {
		return errors.New("current association lacks the plan-bound staged source receipt")
	}
	return nil
}

func sameManagedCheckpointAssociation(a, b CheckpointVerifiedUnitAssociation) bool {
	ai, bi := a.Identity, b.Identity
	ac, bc := a.Custody, b.Custody
	return a.Invocation == b.Invocation && a.ControlGroup == b.ControlGroup &&
		ai.EvidenceKind == bi.EvidenceKind && ai.Endpoint == bi.Endpoint && ai.ServiceUnit == bi.ServiceUnit &&
		ai.BootID == bi.BootID && ai.PID == bi.PID && ai.ProcessStartTicks == bi.ProcessStartTicks &&
		ai.ListenerIP == bi.ListenerIP && ai.ListenerPort == bi.ListenerPort && ai.ListenerSocketInode == bi.ListenerSocketInode &&
		ai.ExecutablePath == bi.ExecutablePath && strings.EqualFold(ai.ExecutableSHA256, bi.ExecutableSHA256) &&
		ai.ExecutableDevice == bi.ExecutableDevice && ai.ExecutableInode == bi.ExecutableInode && ai.ExecutableSize == bi.ExecutableSize &&
		ai.ModelPath == bi.ModelPath && strings.EqualFold(ai.ModelSHA256, bi.ModelSHA256) &&
		ai.ModelDevice == bi.ModelDevice && ai.ModelInode == bi.ModelInode && ai.ModelSize == bi.ModelSize &&
		ac.EvidenceKind == bc.EvidenceKind && ac.ModelArgument == bc.ModelArgument && ac.ArgvSHA256 == bc.ArgvSHA256 &&
		ac.BindingSHA256 == bc.BindingSHA256 && ac.Nonce == bc.Nonce && ac.Endpoint == bc.Endpoint &&
		ac.ServiceUnit == bc.ServiceUnit && ac.UnitAssociation == bc.UnitAssociation && ac.BootID == bc.BootID &&
		ac.PID == bc.PID && ac.ProcessStartTicks == bc.ProcessStartTicks && ac.ListenerSocketInode == bc.ListenerSocketInode &&
		ac.ExecutablePath == bc.ExecutablePath && strings.EqualFold(ac.ExecutableSHA256, bc.ExecutableSHA256) && ac.ActualAlias == bc.ActualAlias &&
		ac.ArtifactPath == bc.ArtifactPath && ac.ArtifactDevice == bc.ArtifactDevice && ac.ArtifactInode == bc.ArtifactInode &&
		ac.ArtifactSize == bc.ArtifactSize && strings.EqualFold(ac.ArtifactSHA256, bc.ArtifactSHA256) && ac.VerityDigest == bc.VerityDigest &&
		ac.ExecutableDevice == bc.ExecutableDevice && ac.ExecutableInode == bc.ExecutableInode && ac.ExecutableSize == bc.ExecutableSize &&
		ac.ExecutableVerityDigest == bc.ExecutableVerityDigest
}

func readManagedCheckpointArgv(pid int) ([]string, error) {
	if pid <= 1 {
		return nil, errors.New("managed process id is invalid")
	}
	raw, err := checkpointReadBounded(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"), 16<<10)
	if err != nil {
		return nil, errors.New("managed process argv is unreadable, truncated, or malformed")
	}
	return parseManagedCheckpointArgv(raw)
}

func observeCheckpointManagedAlias(ctx context.Context, endpoint CheckpointLaunchEndpoint, expected string) (string, error) {
	if ctx == nil || expected == "" || len(expected) > 128 || !checkpointLaunchAliasRE.MatchString(expected) {
		return "", errors.New("managed alias observation request is invalid")
	}
	if endpoint.Host != "127.0.0.1" && endpoint.Host != "::1" || endpoint.Port < 1 || endpoint.Port > 65535 {
		return "", errors.New("managed alias endpoint is not the pinned loopback listener")
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transport := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(bounded, http.MethodGet, "http://"+net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))+"/v1/models", nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("observe current backend model alias: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", errors.New("current backend model endpoint returned unsupported status")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, checkpointManagedHTTPMax+1))
	if err != nil || len(body) == 0 || len(body) > checkpointManagedHTTPMax {
		return "", errors.New("current backend model response is empty or oversized")
	}
	alias, err := parseManagedCheckpointModelList(body, expected)
	if err != nil || alias != expected {
		return "", errors.New("current backend model alias is absent, ambiguous, or differs from the fixed plan")
	}
	return alias, nil
}

func observeManagedCheckpointFootprint(ctx context.Context, pid int, expectedStartTicks uint64, placement CheckpointDevicePlacement) (int64, int64, error) {
	if ctx == nil || pid <= 1 || expectedStartTicks == 0 || !checkpointGPUUUIDRE.MatchString(placement.ChildMaskUUID) {
		return 0, 0, errors.New("current managed process footprint request is invalid")
	}
	startBefore, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || startBefore != expectedStartTicks {
		return 0, 0, errors.New("managed PID incarnation changed before physical footprint attribution")
	}
	if err := verifyCheckpointDirectPIDNamespace(ctx, pid); err != nil {
		return 0, 0, err
	}
	processes, err := runCheckpointGPUProcessInventory(ctx)
	if err != nil {
		return 0, 0, err
	}
	var found *checkpointGPUProcess
	for index := range processes {
		if processes[index].PID != pid {
			continue
		}
		if found != nil || processes[index].UUID != placement.ChildMaskUUID {
			return 0, 0, errors.New("managed PID has absent, duplicate, or cross-device physical attribution")
		}
		found = &processes[index]
	}
	if found == nil || found.UsedBytes <= 0 {
		return 0, 0, errors.New("managed PID has no current physical GPU footprint")
	}
	rss, err := readCheckpointProcessRSS(ctx, pid)
	if err != nil || rss <= 0 {
		return 0, 0, errors.New("managed PID has no bounded current host RSS measurement")
	}
	startAfter, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || startAfter != expectedStartTicks {
		return 0, 0, errors.New("managed PID incarnation changed during physical footprint attribution")
	}
	return found.UsedBytes, rss, nil
}

func observeNestedManagedCheckpointFootprint(ctx context.Context, pid int, expectedStartTicks uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (int64, int64, error) {
	return observeNestedManagedCheckpointFootprintUsing(ctx, pid, expectedStartTicks, plan, placement, observeCheckpointHostGPUAttribution)
}

func observeNestedManagedCheckpointFootprintLocalObserver(ctx context.Context, pid int, expectedStartTicks uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (int64, int64, error) {
	return observeNestedManagedCheckpointFootprintUsing(ctx, pid, expectedStartTicks, plan, placement, observeCheckpointHostGPUAttributionLocalObserver)
}

func observeNestedManagedCheckpointFootprintUsing(ctx context.Context, pid int, expectedStartTicks uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, observe func(context.Context, int, uint64, CheckpointLaunchPlan, CheckpointDevicePlacement) (checkpointHostGPUObservation, error)) (int64, int64, error) {
	if ctx == nil || pid <= 1 || expectedStartTicks == 0 || plan.Placement == nil {
		return 0, 0, errors.New("nested managed footprint request is incomplete")
	}
	startBefore, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || startBefore != expectedStartTicks {
		return 0, 0, errors.New("nested managed PID incarnation changed before host attribution")
	}
	if observe == nil {
		return 0, 0, errors.New("nested host GPU attribution route is unavailable")
	}
	observation, err := observe(ctx, pid, expectedStartTicks, plan, placement)
	if err != nil {
		return 0, 0, err
	}
	rss, err := readCheckpointProcessRSS(ctx, pid)
	if err != nil || rss <= 0 {
		return 0, 0, errors.New("nested managed PID has no bounded current host RSS measurement")
	}
	startAfter, err := checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)
	if err != nil || startAfter != expectedStartTicks {
		return 0, 0, errors.New("nested managed PID incarnation changed during host attribution")
	}
	return observation.Bytes, rss, nil
}

func openCheckpointCustodyStoreReadOnly(plan CheckpointLaunchPlan) (*CheckpointCustodyStore, error) {
	if plan.Custody.Root != checkpointFixedCustodyRoot || plan.Custody.MaxArtifactBytes <= 0 || plan.Custody.MaxStagingBytes <= 0 {
		return nil, errors.New("managed custody root or quotas differ from fixed local policy")
	}
	root := plan.Custody.Root
	paths := []string{root, filepath.Join(root, "models"), filepath.Join(root, "launchers"), filepath.Join(root, "receipts")}
	ids := make([][2]uint64, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			return nil, errors.New("existing custody directories are missing or unsafe")
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Getuid() {
			return nil, errors.New("existing custody directory owner is unsupported")
		}
		ids = append(ids, [2]uint64{uint64(st.Dev), st.Ino})
	}
	lockPath := filepath.Join(root, "custody.lock")
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() || lockInfo.Mode()&os.ModeSymlink != 0 || lockInfo.Mode().Perm() != 0600 || lockInfo.Size() != 0 {
		return nil, errors.New("existing custody synchronization lock is missing or unsafe")
	}
	lockStat, ok := lockInfo.Sys().(*syscall.Stat_t)
	if !ok || int(lockStat.Uid) != os.Getuid() || lockStat.Nlink != 1 {
		return nil, errors.New("existing custody synchronization lock identity is unsupported")
	}
	store := &CheckpointCustodyStore{root: root, maxBytes: plan.Custody.MaxArtifactBytes, maxStagingBytes: plan.Custody.MaxStagingBytes, reserve: plan.Custody.ReserveBytes}
	store.rootDevice, store.rootInode = ids[0][0], ids[0][1]
	store.modelsDevice, store.modelsInode = ids[1][0], ids[1][1]
	store.launchersDevice, store.launchersInode = ids[2][0], ids[2][1]
	store.receiptsDevice, store.receiptsInode = ids[3][0], ids[3][1]
	return store, nil
}
