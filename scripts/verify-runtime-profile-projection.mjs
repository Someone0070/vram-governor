#!/usr/bin/env node

import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = process.cwd();
const owned = [
  'internal/workloads/manager.go',
  'internal/workloads/manager_test.go',
  'internal/workloads/residency.go',
  'internal/api/node_commands.go',
  'internal/api/node_commands_test.go',
  'internal/api/ws.go',
  'internal/api/ws_test.go',
  'scripts/verify-runtime-profile-projection.mjs',
];

function fail(message) {
  console.error(`FAIL: ${message}`);
  process.exitCode = 1;
}

function readOwned(relative) {
  const filename = path.join(root, relative);
  if (!existsSync(filename)) throw new Error(`owned source is missing: ${relative}`);
  return readFileSync(filename, 'utf8');
}

function section(source, start, end) {
  const from = source.indexOf(start);
  if (from < 0) return '';
  const to = source.indexOf(end, from + start.length);
  return to < 0 ? source.slice(from) : source.slice(from, to);
}

function barrierFailureCleanupIsSafe(apiTest) {
  const test = section(apiTest, 'func TestRuntimeProfileProjectionBeforeWaiterAdmission(', '\nfunc ');
  if (!test) return false;
  const allocations = section(test, 'if barrierCase {', '\n\t\t\t}');
  const submitStart = test.indexOf('barrierSubmitStarted = true');
  const submitGo = test.indexOf('go func() {', submitStart);
  const resultStart = test.indexOf('resultHandlerStarted = true');
  const resultGo = test.indexOf('go func() {', resultStart);
  const configureStart = test.indexOf('configureStarted = true');
  const configureGo = test.indexOf('go func() {', configureStart);
  const registrationStart = test.indexOf('registrationStarted = true');
  const registrationGo = test.indexOf('go func() {', registrationStart);
  const settlement = section(test, 'settleBarrierWorkers := func() bool {', '\n\t\t\tdefer func() {');
  const outerCleanup = section(test, 'defer func() {\n\t\t\t\tif barrierCase && !barrierCleanupSafe {', '\n\t\t\t}()');
  const failureDefer = section(test, '\n\t\t\tdefer func() {\n\t\t\t\tif barrierCase && !barrierCleanupSafe {\n\t\t\t\t\tbarrierCleanupSafe = settleBarrierWorkers()', '\n\t\t\t}()');
  const failureDeferStart = test.indexOf('\n\t\t\tdefer func() {\n\t\t\t\tif barrierCase && !barrierCleanupSafe {\n\t\t\t\t\tbarrierCleanupSafe = settleBarrierWorkers()');
  const outerDeferStart = test.indexOf('defer func() {\n\t\t\t\tif barrierCase && !barrierCleanupSafe {');
  const connMutation = outerCleanup.indexOf('connection.conn = nil');
  const cleanupCall = outerCleanup.indexOf('cleanup()');
  const cleanupReturn = outerCleanup.indexOf('return');
  const releaseCAS = settlement.indexOf('releaseResult()');
  const releaseSnapshot = settlement.indexOf('residencySnapshotStore.releaseSnapshot()');
  const cancelSubmit = settlement.indexOf('cancelBarrierSubmit()');
  const cancelConfigure = settlement.indexOf('cancelConfigure()');
  const deadline = settlement.indexOf('deadline := time.Now().Add(3 * time.Second)');
  const resultJoin = settlement.indexOf('resultJoined := join(resultDone, resultHandlerStarted)');
  const registrationJoin = settlement.indexOf('registrationJoined := join(registrationDone, registrationStarted)');
  const configureJoin = settlement.indexOf('configureWorkerJoined := join(configureJoined, configureStarted)');
  const submitJoin = settlement.indexOf('submitJoined := join(barrierSubmitJoined, barrierSubmitStarted)');
  const joinReturn = settlement.indexOf('return resultJoined && registrationJoined && configureWorkerJoined && submitJoined');
  const timeoutTimer = settlement.indexOf('timer := time.NewTimer(remaining)');
  const timeoutCase = settlement.indexOf('case <-timer.C:', timeoutTimer);
  const startedAssignmentsAreBeforeGo = (flag, goAt) => {
    const at = test.indexOf(flag);
    return at >= 0 && goAt > at;
  };
  const workerStarts = [submitGo, resultGo, configureGo, registrationGo];
  const allChannelsPreallocated = [
    'barrierSubmitResult = make(chan submitCompletion, 1)',
    'barrierSubmitJoined = make(chan struct{})',
    'resultDone = make(chan struct{})',
    'registrationDone = make(chan struct{})',
    'configureDone = make(chan error, 1)',
    'configureJoined = make(chan struct{})',
  ].every((token) => allocations.includes(token));
  const closeNotifyOrder = (goAt, closeToken, workToken) => {
    const end = test.indexOf('}()', goAt);
    const body = goAt < 0 || end < 0 ? '' : test.slice(goAt, end);
    return body.indexOf(closeToken) >= 0 && body.indexOf(closeToken) < body.indexOf(workToken);
  };
  return allChannelsPreallocated &&
    workerStarts.every((at) => at > 0 && test.indexOf('if barrierCase {') < at) &&
    startedAssignmentsAreBeforeGo('barrierSubmitStarted = true', submitGo) &&
    startedAssignmentsAreBeforeGo('resultHandlerStarted = true', resultGo) &&
    startedAssignmentsAreBeforeGo('configureStarted = true', configureGo) &&
    startedAssignmentsAreBeforeGo('registrationStarted = true', registrationGo) &&
    !test.includes('resultDone := make(chan') && !test.includes('registrationDone := make(chan') &&
    !test.includes('barrierSubmitJoined := make(chan') && !test.includes('configureDone := make(chan') &&
    !test.includes('configureJoined := make(chan') &&
    closeNotifyOrder(submitGo, 'defer close(barrierSubmitJoined)', 'manager.Submit(barrierSubmitCtx, request)') &&
    closeNotifyOrder(resultGo, 'defer close(resultDone)', 'server.handleNodeCommandResult(') &&
    closeNotifyOrder(configureGo, 'defer close(configureJoined)', 'manager.ConfigureResidency(configureCtx,') &&
    closeNotifyOrder(registrationGo, 'defer close(registrationDone)', 'manager.RegisterTarget(replacement)') &&
    test.includes('configureCtx, cancel := context.WithCancel(configureOwnerCtx)') &&
    test.includes('configureDone <- configureErr') &&
    releaseCAS >= 0 && releaseSnapshot > releaseCAS && cancelSubmit > releaseSnapshot &&
    cancelConfigure > cancelSubmit && deadline > cancelConfigure &&
    timeoutTimer > deadline && timeoutCase > timeoutTimer && settlement.indexOf('return false', timeoutCase) > timeoutCase &&
    resultJoin > deadline && registrationJoin > resultJoin && configureJoin > registrationJoin && submitJoin > configureJoin && joinReturn > submitJoin &&
    !settlement.includes('return join(resultDone, resultHandlerStarted) &&') &&
    outerDeferStart >= 0 && failureDeferStart > outerDeferStart && failureDeferStart < Math.min(...workerStarts) &&
    cleanupReturn >= 0 && cleanupReturn < connMutation && connMutation < cleanupCall &&
    outerCleanup.includes('if barrierCase && !barrierCleanupSafe {') &&
    failureDefer.includes('barrierCleanupSafe = settleBarrierWorkers()') &&
    failureDefer.includes('if !barrierCleanupSafe {') &&
    test.includes('barrierCleanupSafe = false') &&
    test.includes('barrierCleanupSafe = settleBarrierWorkers()') &&
    test.includes('if !barrierCleanupSafe {\n\t\t\t\t\tt.Fatal("barrier workers did not settle before manager/server cleanup")');
}

function resultCASBarrierFixtureIsSafe(apiTests) {
  const test = section(apiTests, 'func TestRuntimeProfileProjectionBeforeWaiterAdmission(', '\nfunc ');
  const setup = section(test, '\n\t\t\tvar server *Server', '\n\t\t\tvar connection *nodeConnection');
  const fixture = section(apiTests, 'func profileResidencyBarrierServer(', '\nfunc profileResultCASBlockingStore');
  const registrationCase = '{name: "registration waits for durable result commit", resultCASLifecycleBarrier: true}';
  const highWaterCase = '{name: "residency high-water writer waits for result projection", resultCASLifecycleBarrier: true, residencyWriterCASBarrier: true}';
  return Boolean(test && setup && fixture) &&
    test.includes(registrationCase) && test.includes(highWaterCase) &&
    setup.includes('if testCase.residencyWriterCASBarrier || testCase.resultCASLifecycleBarrier {') &&
    setup.includes('server, manager, residencySnapshotStore, cleanup = profileResidencyBarrierServer(t)') &&
    setup.includes('} else {\n\t\t\t\tserver, manager, cleanup = testServer(t)') &&
    fixture.includes('backing := store.NewMemoryStore()') &&
    fixture.includes('manager := workloads.NewManager(logger, residencyStore, time.Second)') &&
    fixture.includes('server := NewServer(&Config{}, logger, backing, nil, nil)') &&
    fixture.includes('server.SetWorkloadManager(manager, residencyStore)') &&
    fixture.includes('manager.SetNodeStore(server.nodes)') &&
    fixture.includes('manager.Start(ctx)') &&
    !/\bt\.TempDir\s*\(|\bt\.Cleanup\s*\(|artifacts\.NewFileStore|SetArtifactStore\s*\(/.test(fixture) &&
    test.includes('manager.Submit(') && test.includes('server.handleNodeCommandResult(') &&
    test.includes('manager.RegisterTarget(replacement)') && !test.includes('server.Handler()');
}

function configureSnapshotOwnerBarrierIsSafe(apiTests) {
  const test = section(apiTests, 'func TestRuntimeProfileProjectionBeforeWaiterAdmission(', '\nfunc ');
  const get = section(apiTests, 'func (s *profileResidencySnapshotBarrierStore) GetModelResidency(', '\nfunc profileResidencyBarrierServer(');
  const arm = test.indexOf('residencySnapshotStore.arm()');
  const unrelatedRead = test.indexOf('residencySnapshotStore.GetModelResidency(context.Background(), target.ID, "model")', arm);
  const unrelatedEnteredCheck = test.indexOf('unrelated reader consumed the ConfigureResidency snapshot barrier', unrelatedRead);
  const ownerContext = test.indexOf('context.WithValue(context.Background(), profileResidencySnapshotBarrierContextKey{}, true)', unrelatedRead);
  const configure = test.indexOf('manager.ConfigureResidency(configureCtx, target.ID, "model"', ownerContext);
  const entered = test.indexOf('case <-residencySnapshotStore.entered:', configure);
  return Boolean(test && get) &&
    apiTests.includes('type profileResidencySnapshotBarrierContextKey struct{}') &&
    get.includes('owner, _ := ctx.Value(profileResidencySnapshotBarrierContextKey{}).(bool)') &&
    get.includes('block := s.armed && owner && err == nil && row != nil && targetID == "node-a-runtime" && model == "model"') &&
    get.indexOf('s.WorkloadStore.GetModelResidency(ctx, targetID, model)') < get.indexOf('close(s.entered)') &&
    arm >= 0 && unrelatedRead > arm && unrelatedEnteredCheck > unrelatedRead && ownerContext > unrelatedEnteredCheck &&
    configure > ownerContext && entered > configure &&
    test.includes('unrelated reader could not observe the durable snapshot') &&
    test.includes('case <-residencySnapshotStore.entered:\n\t\t\t\t\t\tt.Fatal("unrelated reader consumed the ConfigureResidency snapshot barrier")\n\t\t\t\t\tdefault:');
}

function inspect(sources) {
  const issues = [];
  const manager = sources['internal/workloads/manager.go'];
  const managerTests = sources['internal/workloads/manager_test.go'];
  const residency = sources['internal/workloads/residency.go'];
  const api = sources['internal/api/node_commands.go'];
  const apiTests = sources['internal/api/node_commands_test.go'];
  const verifier = sources['scripts/verify-runtime-profile-projection.mjs'];
  const linuxBoundary = sources['internal/api/node_commands_linux_test.go'];
  const workloadTests = sources['internal/api/workloads_http_test.go'];
  const ensure = section(manager, 'func (m *Manager) ensureRuntimeProfile(', 'type targetEstimate struct');
  const projector = section(manager, 'func (m *Manager) ProjectRuntimeProfileCommandResult(', 'func projectedRuntimeProfileTarget(');
  const admission = section(manager, 'func (m *Manager) reserveTarget(', 'func (m *Manager) validateActivePlacementBytes(');
  const tryAdmit = section(manager, 'func (m *Manager) tryAdmit(', 'func (m *Manager) reserveTarget(');
  const slots = section(manager, 'func (m *Manager) availableSlots(', 'func (m *Manager) boundTarget(');
  const execute = section(api, 'func (s *Server) executeNodeCommand(', '// ExecuteNodeCommand is the narrow production hook');
  const handler = section(api, 'func (s *Server) handleNodeCommandResult(', 'func (s *Server) projectRuntimeProfileResult(');
  const settle = section(api, 'func (s *Server) settleUncertainOriginal(', 'func nodeCommandReplayMatches(');
  const durableGuard = section(api, 'func (s *Server) rejectUnresolvedRuntimeProfileCommand(', '// ExecuteNodeCommand is the narrow production hook');
  const ticketGuard = section(api, 'func (s *Server) requireRuntimeProfileDispatchTicket(', '// ExecuteNodeCommand is the narrow production hook');
  const dispatchClaim = section(manager, 'func (m *Manager) ClaimRuntimeProfileDispatch(', '// RuntimeProfileDispatchAllowed');
  const httpCreate = section(api, 'func (s *Server) handleCreateNodeCommand(', 'func (s *Server) handleListNodeCommands(');
  const residentSetter = section(residency, 'func (m *Manager) setTargetResident(', 'func (m *Manager) markModelUsed(');
  const generationFence = section(manager, 'func (m *Manager) reconcileResidencyGeneration(', 'func (m *Manager) runtimeProfileHasPendingLocked(');
  const generationContextFence = section(manager, 'func (m *Manager) reconcileResidencyGenerationContext(', 'func (m *Manager) runtimeProfileHasPendingLocked(');
  const targetRegistration = section(manager, 'func (m *Manager) RegisterTarget(', 'func targetExecutionFingerprint(');
  const targetReplacement = section(manager, 'func (m *Manager) replaceTargetLocked(', 'func (m *Manager) UpdateAcceleratorCapacity(');
  const exhaustedInvalidation = section(manager, 'func (m *Manager) invalidateTargetAtExhaustedGenerationLocked(', 'func (m *Manager) UpdateAcceleratorCapacity(');
  const capacityUpdate = section(manager, 'func (m *Manager) UpdateAcceleratorCapacity(', 'func (m *Manager) ReconcileNodeTargets(');
  const nodeRetirement = section(manager, 'func (m *Manager) ReconcileNodeTargets(', 'func (m *Manager) Targets()');
  const profileTransitionBegin = section(manager, 'func (m *Manager) beginRuntimeProfileTransition(', 'func (m *Manager) ValidateRuntimeProfileCommandResult(');
  const transitionModel = section(residency, 'func (m *Manager) transitionModel(', 'func (m *Manager) nodeReady(');
  const configureResidency = section(residency, 'func (m *Manager) ConfigureResidency(', 'func transitionsForIDs(');

  if (!ensure || /CapacitySource\s*=\s*"runtime-profile:"\s*\+\s*desired\.ID/.test(ensure) || /CapacityVerified\s*=\s*true/.test(ensure)) {
    issues.push('manager switch path still fabricates verified capacity from the desired profile');
  }
  for (const token of ['beginRuntimeProfileTransition', 'ProjectRuntimeProfileCommandResult', 'transition.commandKey']) {
    if (!ensure.includes(token)) issues.push(`manager switch path is missing ${token}`);
  }
  if (ensure.indexOf('m.mu.RUnlock()') > ensure.indexOf('control(ctx, nodeID, "switch_runtime_profile"') || ensure.indexOf('control(ctx, nodeID, "switch_runtime_profile"') < 0) {
    issues.push('manager state lock appears to span external profile command execution');
  }
  for (const token of ['transition.expectedGeneration', 'transition.projectedGeneration', 'runtime:/slots', 'CapabilitiesVerified', 'ActiveRuntimeProfile', 'RuntimeProfiles', 'retiredTargets']) {
    if (!projector.includes(token)) issues.push(`authoritative projector is missing ${token}`);
  }
  if (!manager.includes('CapacitySource = "runtime-profile:pending"') || !manager.includes('current.Slots = 0') || !manager.includes('current.ContextLimit = 0')) {
    issues.push('pending transition does not revoke current verified context and slots');
  }
  if (!manager.includes('discarding stale target refresh after runtime profile projection')) {
    issues.push('older profile registrations can overwrite a projected runtime profile');
  }
  const durableCapacityGuard = section(manager, 'func (m *Manager) runtimeProfileQuarantineReason(', 'func (m *Manager) ReconcileNodeTargets(');
  if (!durableCapacityGuard.includes('ListNodeCommandRecovery') || !durableCapacityGuard.includes('reduceRuntimeProfileHistory')) {
    issues.push('target registration does not fail closed on unresolved durable profile commands');
  }
  if (!manager.includes('func runtimeProfileCommandHasAcceptedResult(') || !manager.includes('CapacitySource != "runtime:/slots"') || !manager.includes('profileMatches == 1')) {
    issues.push('restart registration can restore capacity without an accepted persisted runtime-slot result');
  }
  if (!manager.includes('runtime-profile:observation_unavailable') || !manager.includes('operator reconciliation is required')) {
    issues.push('durable profile quarantine bypasses slot/admission checks');
  }
  if (!manager.includes('historyBasisGeneration+1 == transition.expectedGeneration') || !manager.includes('target = transition.historyBasis') || !managerTests.includes('TestRuntimeProfileRepeatedSwitchHistoryUsesPretransitionBasis')) {
    issues.push('subsequent same-route physical dispatch lacks its exact verified pretransition history basis');
  }
  if (!tryAdmit.includes('profilePending || profileBlocker') || !tryAdmit.includes('runtime-profile:pending') || !managerTests.includes('TestRuntimeProfileZeroContextAdmissionCannotMutatePendingGeneration')) {
    issues.push('zero-context pending admission can mutate durable HOT residency before transition rejection');
  }
  if (!tryAdmit.includes('append(append([]string(nil), current.ResidentModels...), req.Model)') || !tryAdmit.includes('m.invalidateTargetAtExhaustedGenerationLocked(target.ID, previous)')) {
    issues.push('durable HOT reconciliation can alias or retain stale resident facts at an exhausted generation');
  }
  if (!residentSetter.includes('lockRuntimeProfileTransitionForTarget(targetID)') || !residentSetter.includes('!profileTransition.projected') || !residentSetter.includes('refreshRuntimeProfileProjectedGenerationLocked(target)') || !manager.includes('func (m *Manager) refreshRuntimeProfileProjectedGenerationLocked(') || !managerTests.includes('TestRuntimeProfileResultClaimFencesResidentGenerationMutation')) {
    issues.push('resident metadata mutation is not fenced against pending/result-commit profile generations');
  }
  if (residentSetter.includes('target.ResidentModels[:0]') || !residentSetter.includes('residentModels := append([]string(nil), target.ResidentModels...)') || !residentSetter.includes('filtered := make([]string, 0, len(residentModels))') || !residentSetter.includes('m.invalidateTargetAtExhaustedGenerationLocked(targetID, m.targets[targetID])') || !managerTests.includes('TestSetTargetResidentExhaustedRemovalDoesNotMutateLiveBackingSlice')) {
    issues.push('failed resident removal can mutate the live backing slice or leave its stale route schedulable');
  }
  if (!generationFence.includes('prior.dispatchMu.Lock()') || !generationFence.includes('prior.resultMu.Lock()') || !generationFence.includes('currentKey != priorKey || currentTicket != prior') || !generationFence.includes('prior != nil && !prior.projected') || !generationFence.includes('m.targetGenerations[target.ID] = generation') || !generationFence.includes('refreshRuntimeProfileProjectedGenerationLocked(current)')) {
    issues.push('durable residency high-water recovery lacks a revalidated current-ticket fence around its generation mutation');
  }
  if (!generationFence.includes('projection.TargetGeneration == ^uint64(0)') || generationFence.indexOf('projection.TargetGeneration == ^uint64(0)') > generationFence.indexOf('generation = projection.TargetGeneration + 1')) {
    issues.push('durable residency high-water recovery can overflow uint64 before rejecting the exhausted generation');
  }
  if (generationFence.indexOf('if prior != nil && !prior.projected') < 0 || generationFence.indexOf('m.targetGenerations[target.ID] = generation') < generationFence.indexOf('if prior != nil && !prior.projected')) {
    issues.push('durable residency high-water recovery can mutate generation before rejecting a pending ticket');
  }
  if (generationFence.includes('GetModelResidency') || generationFence.includes('UpsertModelResidency') || generationFence.includes('CompareAndSwapModelResidency')) {
    issues.push('residency high-water ticket locks span a durable store operation');
  }
  const commitContextCheck = generationContextFence.indexOf('if err := ctx.Err(); err != nil {');
  const commitAssignment = generationContextFence.indexOf('m.targetGenerations[target.ID] = generation');
  const commitRefresh = generationContextFence.indexOf('refreshRuntimeProfileProjectedGenerationLocked(current)');
  const commitLocks = [
    generationContextFence.indexOf('prior.dispatchMu.Lock()'),
    generationContextFence.indexOf('prior.resultMu.Lock()'),
    generationContextFence.indexOf('m.residencyAdmissionMu.Lock()'),
    generationContextFence.indexOf('fence.Lock()'),
    generationContextFence.indexOf('m.mu.Lock()'),
    generationContextFence.indexOf('if currentKey != priorKey || currentTicket != prior {'),
  ];
  const canceledCommitBranch = commitContextCheck < 0 ? '' : generationContextFence.slice(commitContextCheck, generationContextFence.indexOf('\n\t\tcurrent, found :=', commitContextCheck));
  const contextWrapper = section(manager, 'func (m *Manager) reconcileResidencyGeneration(', 'func (m *Manager) reconcileResidencyGenerationContext(');
  if (!contextWrapper.includes('m.reconcileResidencyGenerationContext(context.Background(), target, projection, expectedGeneration)') ||
      !generationContextFence.includes('if ctx == nil {') || commitLocks.some((at) => at < 0) ||
      !commitLocks.every((at, index) => index === 0 || at > commitLocks[index - 1]) ||
      commitContextCheck <= commitLocks[commitLocks.length - 1] || commitAssignment <= commitContextCheck || commitRefresh < commitAssignment ||
      !canceledCommitBranch.includes('m.mu.Unlock()') || !canceledCommitBranch.includes('fence.Unlock()') ||
      !canceledCommitBranch.includes('m.residencyAdmissionMu.Unlock()') || !canceledCommitBranch.includes('prior.resultMu.Unlock()') ||
      !canceledCommitBranch.includes('prior.dispatchMu.Unlock()') || !canceledCommitBranch.includes('return target, expectedGeneration, err')) {
    issues.push('high-water commit must preserve legacy callers and check Configure cancellation after all current ticket/target locks but before generation or projected-ticket publication');
  }
  if (!targetReplacement.includes('m.targetGenerations[target.ID] == ^uint64(0)') || !targetReplacement.includes('return fmt.Errorf("target %s execution generation is exhausted", target.ID)') || targetReplacement.indexOf('m.targetGenerations[target.ID] == ^uint64(0)') > targetReplacement.indexOf('m.targetGenerations[target.ID]++') || targetReplacement.indexOf('return fmt.Errorf') > targetReplacement.indexOf('m.targets[target.ID] = target')) {
    issues.push('shared target replacement can wrap or publish changed facts at an exhausted generation');
  }
  if (!targetRegistration.includes('publishGeneration == ^uint64(0)') || !targetRegistration.includes('m.targetGenerations[target.ID] == ^uint64(0)') || !targetRegistration.includes('durableGeneration - 1') || !targetRegistration.includes('durableGenerationAny') || !targetRegistration.includes('registrationSnapshotGeneration') || !targetRegistration.includes('rejecting target resurrection because its exhausted generation is retired') || targetRegistration.indexOf('publishGeneration == ^uint64(0)') > targetRegistration.indexOf('m.targetGenerations[target.ID] = publishGeneration')) {
    issues.push('target registration does not fail closed on changed MaxUint64 durable identity while retaining exact-fingerprint recovery');
  }
  const registrationPublishIndex = targetRegistration.indexOf('if err := m.replaceTargetLocked(target);');
  const prematureTargetBlockerMutation = targetRegistration.indexOf('m.runtimeProfileBlockedTargets[target.ID] = ""');
  if (!targetRegistration.includes('prospectiveTargetBlocker') || !targetRegistration.includes('prospectiveNodeBlocker') || !targetRegistration.includes('prospectiveCardBlocker') || !targetRegistration.includes('m.runtimeProfileHasPendingLocked(target.NodeID, "")') || !targetRegistration.includes('m.runtimeProfileHasPendingLocked("", target.AcceleratorID)') || registrationPublishIndex < 0 || registrationPublishIndex > targetRegistration.indexOf('m.runtimeProfileBlockedTargets[target.ID] = prospectiveTargetBlocker') || (prematureTargetBlockerMutation >= 0 && prematureTargetBlockerMutation < registrationPublishIndex)) {
    issues.push('target registration mutates blocker state before fallible generation publication or clears a pending alias blocker');
  }
  if (!exhaustedInvalidation.includes('m.targetGenerations[targetID] != ^uint64(0)') || !exhaustedInvalidation.includes('m.retiredTargets[targetID] = target') || !exhaustedInvalidation.includes('delete(m.targets, targetID)') || !exhaustedInvalidation.includes('m.runtimeProfileBlockedCards[target.AcceleratorID]') || !targetRegistration.includes('m.invalidateTargetAtExhaustedGenerationLocked(target.ID, previous)')) {
    issues.push('changed exhausted-generation registration can leave its stale live route schedulable');
  }
  if (!capacityUpdate.includes('m.invalidateTargetAtExhaustedGenerationLocked(id, previous)') || !capacityUpdate.includes('target.AcceleratorVRAMMB = vramTotalMB') || !exhaustedInvalidation.includes('m.pendingObservationGeneration++')) {
    issues.push('authoritative lower VRAM telemetry can leave stale exhausted-generation capacity schedulable');
  }
  if (!nodeRetirement.includes('m.targetGenerations[snapshot.id] == ^uint64(0)') || nodeRetirement.indexOf('m.targetGenerations[snapshot.id] == ^uint64(0)') > nodeRetirement.indexOf('m.targetGenerations[snapshot.id]++')) {
    issues.push('node route retirement can wrap an exhausted target generation');
  }
  if (!profileTransitionBegin.includes('generation >= ^uint64(0)-1') || profileTransitionBegin.indexOf('generation >= ^uint64(0)-1') > profileTransitionBegin.indexOf('m.replaceTargetLocked(current)')) {
    issues.push('runtime profile transition can begin without room for both pending and projected generation fences');
  }
  if (!transitionModel.includes('hasExact(target.ResidentModels, model) != willBeResident') || !transitionModel.includes('targetGeneration == ^uint64(0)') || transitionModel.indexOf('targetGeneration == ^uint64(0)') > transitionModel.indexOf('AllocateResidencyTransition')) {
    issues.push('residency lifecycle can dispatch before its exhausted resident-model generation mutation is rejected');
  }
  if (!transitionModel.includes('reconcileResidencyGeneration') || /m\.targetGenerations\s*\[/.test(transitionModel)) {
    issues.push('transitionModel still mutates the live high-water generation outside the shared ticket fence');
  }
  if (!configureResidency.includes('reconcileResidencyGeneration') || /m\.targetGenerations\s*\[/.test(configureResidency)) {
    issues.push('ConfigureResidency still mutates the live high-water generation outside the shared ticket fence');
  }
  const configureRead = configureResidency.indexOf('m.store.GetModelResidency(ctx, targetID, model)');
  const configureOperation = configureResidency.indexOf('m.beginResidencyOperation(ctx)');
  const configureReconcile = configureResidency.indexOf('m.reconcileResidencyGenerationContext(ctx, target, residency, targetGeneration)');
  const configureGeneration = configureResidency.indexOf('targetGeneration := m.targetGeneration(targetID)');
  if (configureGeneration < 0 || configureGeneration > configureRead || configureRead < 0 || configureOperation <= configureRead || configureReconcile <= configureOperation) {
    issues.push('ConfigureResidency must capture its target/generation and read the durable snapshot before acquiring the operation fence, then reconcile only inside it');
  }
  if (!configureResidency.includes('if ctx == nil {') || configureResidency.indexOf('if ctx == nil {') > configureResidency.indexOf('ctx.Err()') ||
      configureResidency.indexOf('if err := ctx.Err(); err != nil {') < 0 ||
      configureResidency.indexOf('if err := ctx.Err(); err != nil {') > configureRead ||
      configureResidency.indexOf('if residency == nil {') < configureRead ||
      configureResidency.indexOf('if residency == nil {') > configureOperation) {
    issues.push('ConfigureResidency does not fail closed on nil/canceled context or a missing pre-operation snapshot');
  }
  const postReadContext = configureResidency.indexOf('if err := ctx.Err(); err != nil {', configureRead);
  const postAcquireContext = configureResidency.indexOf('if err := ctx.Err(); err != nil {', configureOperation);
  const postReconcileContext = configureResidency.indexOf('if err := ctx.Err(); err != nil {', configureReconcile);
  const targetFence = configureResidency.indexOf('if !m.targetFenceMatches(target, targetGeneration) {');
  const firstProjectionWrite = configureResidency.indexOf('m.persistResidencyProjection(ctx, residency, residencyRevision)');
  if (postReadContext <= configureRead || postReadContext >= configureOperation || postAcquireContext <= configureOperation || postAcquireContext >= configureReconcile || postReconcileContext <= configureReconcile || targetFence <= configureReconcile || firstProjectionWrite <= targetFence) {
    issues.push('ConfigureResidency is missing post-read/post-acquire cancellation checks or its post-reconcile target/CAS fence');
  }
  if (configureOperation >= 0 && /(?:reconcileResidencyGeneration|persistResidencyProjection|reserveTarget|transitionModel)\s*\(/.test(configureResidency.slice(0, configureOperation))) {
    issues.push('ConfigureResidency performs reconciliation or a mutation before acquiring its operation fence');
  }
  const canceledHighWaterTest = section(managerTests, 'func TestResidencyHighWaterRecoveryAdvancesSettledGenerationMonotonically(', '\nfunc ');
  const claimAcquire = canceledHighWaterTest.indexOf('cancelManager.ClaimRuntimeProfileResult(transition.commandKey, transition.nodeID');
  const claimProject = canceledHighWaterTest.indexOf('claim.Project(runtimeProfileProjectionResult(cancelTarget))');
  const highWaterSeed = canceledHighWaterTest.indexOf('highWater.TargetGeneration = preCancelGeneration + 8');
  const cancelStart = canceledHighWaterTest.indexOf('cancelCtx, cancelConfigure := context.WithCancel(ctx)');
  const cancelGo = canceledHighWaterTest.indexOf('go func() {', cancelStart);
  const cancelFence = canceledHighWaterTest.indexOf('if !configureBlockedOnClaim {', cancelGo);
  const cancelReleaseBlock = canceledHighWaterTest.indexOf('\n\tcancelConfigure()\n\tclaim.Release()\n\tselect {', cancelFence);
  const cancelCall = cancelReleaseBlock < 0 ? -1 : cancelReleaseBlock + 2;
  const claimRelease = cancelReleaseBlock < 0 ? -1 : canceledHighWaterTest.indexOf('claim.Release()', cancelCall);
  const canceledJoin = canceledHighWaterTest.indexOf('case configureErr := <-configureDone:', claimRelease);
  const noLiveMutation = canceledHighWaterTest.indexOf('got != preCancelGeneration', canceledJoin);
  const noProjectedMutation = canceledHighWaterTest.indexOf('postCancelProjectedGeneration != preCancelProjectedGeneration', noLiveMutation);
  const noDurableMutation = canceledHighWaterTest.indexOf('!reflect.DeepEqual(seeded, durableAfter)', noProjectedMutation);
  if (claimAcquire < 0 || claimProject <= claimAcquire || highWaterSeed <= claimProject ||
      cancelStart <= highWaterSeed || cancelGo <= cancelStart || cancelFence <= cancelGo || cancelCall <= cancelFence ||
      claimRelease <= cancelCall || canceledJoin <= claimRelease || !canceledHighWaterTest.includes('errors.Is(configureErr, context.Canceled)') ||
      noLiveMutation <= canceledJoin || noProjectedMutation <= noLiveMutation || noDurableMutation <= noProjectedMutation ||
      !canceledHighWaterTest.includes('transition.dispatchMu.TryLock()') || !canceledHighWaterTest.includes('configureBlockedOnClaim = true') ||
      !canceledHighWaterTest.includes('cancelManager.targetGeneration(cancelTarget.ID)') || !canceledHighWaterTest.includes('preCancelProjectedGeneration := transition.projectedGeneration') ||
      !canceledHighWaterTest.includes('case <-time.After(time.Second):') || !canceledHighWaterTest.includes('configureDone <- configureErr') ||
      !canceledHighWaterTest.includes('defer func() {\n\t\tcancelConfigure()\n\t\tclaim.Release()') ||
      !canceledHighWaterTest.includes('case <-configureDone:\n\t\t\t\tconfigureSettled = true') ||
      !canceledHighWaterTest.includes('t.Errorf("canceled ConfigureResidency worker did not join during test cleanup")')) {
    issues.push('existing high-water test lacks a bounded cancel-while-result-claim-held case proving no live generation, projected ticket, or durable-row mutation');
  }
  const highWaterAPITest = section(apiTests, 'func TestRuntimeProfileProjectionBeforeWaiterAdmission(', '\nfunc ');
  const resultCASCreate = highWaterAPITest.indexOf('resultCASStore = &profileResultCASBlockingStore{');
  const resultReleaseOnce = highWaterAPITest.indexOf('var releaseResultOnce sync.Once', resultCASCreate);
  const resultReleaseHelper = highWaterAPITest.indexOf('releaseResult = func()', resultReleaseOnce);
  const resultReleaseOnceDo = highWaterAPITest.indexOf('releaseResultOnce.Do(func() { close(resultCASStore.release) })', resultReleaseHelper);
  const resultStoreInstall = highWaterAPITest.indexOf('server.workloadStore = resultCASStore', resultReleaseHelper);
  const resultProjectionWait = highWaterAPITest.indexOf('case <-resultDone');
  const resultCASRelease = highWaterAPITest.lastIndexOf('releaseResult()', resultProjectionWait);
  const snapshotRelease = highWaterAPITest.indexOf('residencySnapshotStore.releaseSnapshot()', resultProjectionWait);
  if (!apiTests.includes('profileResidencySnapshotBarrierStore') || !highWaterAPITest.includes('residencySnapshotStore.entered') || !highWaterAPITest.includes('writer using its preprojection snapshot did not fail closed') || !highWaterAPITest.includes('new writer snapshot after result projection did not recover settled high-water') || resultCASCreate < 0 || resultReleaseOnce < resultCASCreate || resultReleaseHelper < resultReleaseOnce || resultReleaseOnceDo < resultReleaseHelper || resultStoreInstall < resultReleaseHelper || resultCASRelease < resultStoreInstall || resultProjectionWait < resultCASRelease || snapshotRelease < resultProjectionWait) {
    issues.push('API high-water race lacks its durable result-CAS barrier, success projection ordering, separate postprojection snapshot release, or fresh settled writer positive control');
  }
  if (!barrierFailureCleanupIsSafe(highWaterAPITest)) {
    issues.push('barrier worker cleanup does not release both barriers, cancel, independently boundedly join every started worker, and guard connection/manager/server cleanup on confirmed joins');
  }
  if (!resultCASBarrierFixtureIsSafe(apiTests)) {
    issues.push('both result-CAS barrier cases must use the existing manual pass-through fixture, keep nonbarriers on testServer, and avoid automatic temp/artifact cleanup');
  }
  if (!configureSnapshotOwnerBarrierIsSafe(apiTests)) {
    issues.push('high-water snapshot barrier can be consumed by an unrelated reader or is not bound to ConfigureResidency context');
  }
  if (highWaterAPITest.includes('time.After(30 * time.Millisecond)')) {
    issues.push('API high-water race still depends on a timing-only negative wait');
  }
  if (highWaterAPITest.includes('time.After(30 * time.Millisecond)')) {
    issues.push('API high-water writer race still depends on a timing-only negative wait');
  }
  const casConflictStart = highWaterAPITest.lastIndexOf('if testCase.resultCASConflict {');
  const casConflictEnd = highWaterAPITest.indexOf('\n\t\t\tif row == nil', casConflictStart);
  const casConflictBranch = casConflictStart < 0 || casConflictEnd < 0 ? '' : highWaterAPITest.slice(casConflictStart, casConflictEnd);
  if (!highWaterAPITest.includes('submitCtx, submitCancel = context.WithTimeout(context.Background(), 2*time.Second)') ||
      !highWaterAPITest.includes('_, _, submitErr := manager.Submit(submitCtx, request)') ||
      !highWaterAPITest.includes('submitContextErr := submitCtx.Err()') ||
      !highWaterAPITest.includes('submitCancel()') ||
      !highWaterAPITest.includes('!errors.Is(submitErr, context.DeadlineExceeded) || submitContextErr != context.DeadlineExceeded') ||
      !casConflictBranch.includes('status != string(domain.NodeCommandSent)') ||
      !casConflictBranch.includes('foundPending := false') ||
      !casConflictBranch.includes('if !foundPending {') ||
      !casConflictBranch.includes('CAS-losing result retired the pending runtime target unexpectedly') ||
      !casConflictBranch.includes('projected.CapacityVerified || projected.ContextLimit != 0 || projected.Slots != 0 || projected.CapacitySource != "runtime-profile:pending"') ||
      !casConflictBranch.includes('row.Status == domain.WorkloadRunning || row.Status == domain.WorkloadSucceeded')) {
    issues.push('durable result CAS-conflict submission is not bounded/settled with exact SENT, pending-zero-capacity, and no-admission assertions');
  }
  if (!managerTests.includes('TestResidencyHighWaterRecoveryRejectsPendingProfileGeneration') || !managerTests.includes('TestResidencyHighWaterRecoveryAdvancesSettledGenerationMonotonically') || !managerTests.includes('TestResidencyHighWaterRecoveryRejectsMaxUint64BeforeLiveMutation') || !managerTests.includes('TestTargetRegistrationPreservesExhaustedDurableGeneration') || !managerTests.includes('TestRuntimeProfileTransitionRejectsInsufficientGenerationSpace') || !apiTests.includes('residency high-water writer waits for result projection')) {
    issues.push('high-water coverage is missing pending-ticket, settled, overflow, registration/replay, or deterministic API success-CAS cases');
  }
  if (!managerTests.includes('TestRuntimeProfileHistoryRetryRestoresCapacityAndKeepsPendingAliasesBlocked') || !managerTests.includes('TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts') || !managerTests.includes('TestSetTargetResidentExhaustedRemovalDoesNotMutateLiveBackingSlice')) {
    issues.push('repair coverage lacks same-manager history recovery, exhausted authoritative-fact invalidation, or failed resident-slice preservation');
  }
  if (!apiTests.includes('TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis')) {
    issues.push('composed API dispatch test for second/third accepted physical switches is missing');
  }
  if (!manager.includes('runtimeProfileBlockedNodes') || !manager.includes('runtimeProfileBlockedCards') || !manager.includes('runtimeProfileBlockedTargets') || !manager.includes('runtimeProfileTargetBlockerLocked')) {
    issues.push('physical node/card uncertainty is not shared across route aliases');
  }
  if (!admission.includes('runtimeProfileTargetBlockerLocked(currentTarget)') || !slots.includes('runtimeProfileTargetBlockerLocked(target)')) {
    issues.push('physical node/card uncertainty is missing from final admission or slot exposure');
  }
  if (!ensure.includes('runtime-profile:observation_unavailable') || !ensure.includes('operator reconciliation is required')) {
    issues.push('scheduler can retry a physical switch while durable profile state is unresolved');
  }
  if (!admission.includes('runtimeProfilePending') || !slots.includes('if pending')) {
    issues.push('manager admission or free-slot projection can bypass a pending profile transition');
  }
  if (!handler.includes('ClaimRuntimeProfileResult(command.IdempotencyKey, command.NodeID, result.Result)')) {
    issues.push('API result handler does not validate evidence before durable success');
  }
  const resultCAS = handler.indexOf('_, updateErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision');
  const projection = handler.indexOf('profileResultClaim.Project(result.Result)');
  if (resultCAS < 0 || projection < resultCAS) {
    issues.push('API projects capacity before the durable result CAS succeeds');
  }
  if (!execute.includes('s.projectRuntimeProfileResult(current, result)')) {
    issues.push('command waiter does not synchronize the idempotent projection');
  }
  if (!settle.includes('profileResultClaim.Project(observed)')) {
    issues.push('authoritative late-result settlement does not project the runtime profile');
  }
  if (!durableGuard.includes('ListNodeCommandRecovery(ctx, nodeID, "")') || !durableGuard.includes('RuntimeProfileHistoryBlocker(nodeID, targetID, history)') || !durableGuard.includes('observation_unavailable') || !manager.includes('row.Attempts == 0 && (row.Status == domain.NodeCommandFailed || row.Status == domain.NodeCommandExpired)')) {
    issues.push('durable command path does not block a second unresolved physical profile switch');
  }
  if (!dispatchClaim.includes('transition.dispatchMu.Lock()') || !manager.includes('runtimeProfileCommandHasAcceptedResult(row)') || !manager.includes('AcceleratorIndex == nil') || !manager.includes('*matched.AcceleratorIndex < 0')) {
    issues.push('profile history, explicit physical identity, or lifecycle dispatch claim is incomplete');
  }
  for (const [name, source] of [['HTTP command creation', httpCreate], ['scheduler command creation', execute]]) {
    if (!source.includes('rejectUnresolvedRuntimeProfileCommand') || !source.includes('requireRuntimeProfileDispatchTicket') || !source.includes('runtimeProfileCommandGuard.Lock()')) {
      issues.push(`${name} bypasses the exact manager ticket or durable unresolved-switch guard`);
    }
  }
  const send = section(api, 'func (s *Server) sendNodeCommand(', 'func (s *Server) handleNodeCommandResult(');
  if (!send.includes('requireRuntimeProfileDispatchTicket')) issues.push('websocket send path lacks the exact current manager transition ticket fence');
  const sendTicket = send.indexOf('requireRuntimeProfileDispatchTicket');
  const sendCAS = send.indexOf('CompareAndSwapNodeCommandRevision');
  const sendWrite = send.indexOf('writeCurrentNodeConnection');
  if (sendTicket < 0 || sendCAS < 0 || sendWrite < 0 || sendTicket > sendCAS || sendTicket > sendWrite) {
    issues.push('websocket send path reaches durable dispatch or transport before ticket authorization');
  }
  if (httpCreate.indexOf('requireRuntimeProfileDispatchTicket') < 0 || httpCreate.indexOf('.CreateNodeCommand(') < 0 || httpCreate.indexOf('requireRuntimeProfileDispatchTicket') > httpCreate.indexOf('.CreateNodeCommand(')) {
    issues.push('raw HTTP profile switch can persist before current-ticket authorization');
  }
  if (execute.indexOf('requireRuntimeProfileDispatchTicket') < 0 || execute.indexOf('.CreateNodeCommand(') < 0 || execute.indexOf('requireRuntimeProfileDispatchTicket') > execute.indexOf('.CreateNodeCommand(')) {
    issues.push('scheduler command path can persist before current-ticket authorization');
  }
  if (!ticketGuard.includes('s.workloads == nil') || !ticketGuard.includes('ClaimRuntimeProfileDispatch')) {
    issues.push('switch dispatch authorization fails open without the exact current manager ticket');
  }
  if (!api.includes('raw admin HTTP') || !api.includes('public way to obtain such a ticket')) {
    issues.push('disabled raw HTTP profile switching is not documented as pending a public ticket API');
  }
  if (!api.includes('node protocol requires operator reconciliation')) {
    issues.push('unknown profile effects are not explicitly left for operator reconciliation');
  }
  for (const token of ['timeout: 8_000', "'go', ['test', '-json', '-count=1', '-timeout=120s', '-run', parentPattern", 'timeout: 130_000', "'start', 'run', 'pass', 'fail', 'skip', 'output', 'pause', 'cont'", 'duplicate Go package start', 'event.Package !== pkg', 'unknown Go event action', 'event.Test === undefined', 'seenRun.set(event.Test, 1)', 'seenPass.set(event.Test, 1)', 'packagePass !== 1']) {
    if (!verifier.includes(token)) issues.push(`bounded exact Go inventory is missing ${token}`);
  }
  if (/\['test',\s*'-json',\s*'-count=1',\s*'\.\/internal\/(?:workloads|api)'/.test(verifier)) {
    issues.push('unit verifier still runs a whole-package test command');
  }
  if (!handler.includes('command.Command == "refresh_capabilities"')) {
    issues.push('switch results still rely on generic capability registration');
  }

  const requiredTests = [
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfilePendingRevokesOldVerifiedSlots'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileReplayIdempotentGeneration'],
    ['internal/workloads/manager_test.go', 'TestLateResultCannotResurrectRetiredTarget'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileObservationFailureStaysUnverified'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileProjectionRejectsWrongNodeAndStaleGeneration'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileUnresolvedTicketBlocksSecondPhysicalSwitch'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryFailureWithholdsRegisteredCapacity'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryRetryRestoresCapacityAndKeepsPendingAliasesBlocked'],
    ['internal/workloads/manager_test.go', 'TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts'],
    ['internal/workloads/manager_test.go', 'TestSetTargetResidentExhaustedRemovalDoesNotMutateLiveBackingSlice'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryRestoresOnlyKnownTerminalEvidence'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileUnknownEffectQuarantinesAlreadyRegisteredCardAliases'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileTransitionWinsRegistrationHistoryRace'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileDispatchFenceRequiresExactOriginatingTicket'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileDispatchClaimExcludesRetirementAndRouteReplacement'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileAcceptedHistoryIsScopedToPhysicalCardAndExactRoute'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryReducerIsOrderIndependent'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileRepeatedSwitchHistoryUsesPretransitionBasis'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileZeroContextAdmissionCannotMutatePendingGeneration'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileResultClaimFencesResidentGenerationMutation'],
    ['internal/workloads/manager_test.go', 'TestResidencyHighWaterRecoveryRejectsPendingProfileGeneration'],
    ['internal/workloads/manager_test.go', 'TestResidencyHighWaterRecoveryAdvancesSettledGenerationMonotonically'],
    ['internal/workloads/manager_test.go', 'TestResidencyHighWaterRecoveryRejectsMaxUint64BeforeLiveMutation'],
    ['internal/workloads/manager_test.go', 'TestTargetRegistrationPreservesExhaustedDurableGeneration'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileTransitionRejectsInsufficientGenerationSpace'],
    ['internal/api/node_commands_test.go', 'TestRuntimeProfileRawHTTPAndWebsocketDispatchFailClosedWithoutCurrentTicket'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryUsesLatestAcceptedAndRetainsUnresolved'],
    ['internal/workloads/manager_test.go', 'TestRuntimeProfileHistoryRejectsAmbiguousAcceptedOrdering'],
    ['internal/api/node_commands_test.go', 'TestRuntimeProfileProjectionBeforeWaiterAdmission'],
    ['internal/api/node_commands_test.go', 'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch'],
    ['internal/api/node_commands_test.go', 'TestRuntimeProfileCommandGuardUsesAcceptedObservationForSucceededHistory'],
    ['internal/api/node_commands_test.go', 'TestRuntimeProfileCommandGuardRejectsAmbiguousAcceptedOrdering'],
    ['internal/api/node_commands_test.go', 'TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis'],
    ['internal/api/ws_test.go', 'TestRegisterQuarantinesRuntimeCapacityAfterManagerRestart'],
  ];
  for (const [filename, testName] of requiredTests) {
    if (!sources[filename].includes(`func ${testName}(`)) issues.push(`required production-path test is missing: ${testName}`);
  }
  const signedBoundary = section(apiTests, 'func runControllerResidencySignedNodeBoundary(t *testing.T) {', '\nfunc runSignedNodeLifecycleBoundary');
  const signedWarmFixture = section(apiTests, 'func newSignedBoundaryNode(t *testing.T, nodeID, initialState, statePath string) *signedBoundaryNode {', '\n\tdiscovery, err :=');
  const restartResultComparator = section(apiTests, 'func signedBoundaryCommandResultJSONEqual(', '\nfunc assertSignedBoundaryCommandResultComparatorControls(');
  const restartComparatorControls = section(apiTests, 'func assertSignedBoundaryCommandResultComparatorControls(', '\nfunc (n *signedBoundaryNode) command(');
  const lifecycleBoundary = section(apiTests, 'func runSignedNodeLifecycleBoundary(t *testing.T) {', '\nfunc runSignedRollbackBoundary');
  const rollbackBoundary = section(apiTests, 'func runSignedRollbackBoundary(t *testing.T) {', '\nfunc runSignedNodeRecoveryBoundary');
  const recoveryBoundary = section(apiTests, 'func runSignedNodeRecoveryBoundary(t *testing.T) {', '\nfunc runSignedControllerWebsocketBoundary');
  const websocketBoundary = section(apiTests, 'func runSignedControllerWebsocketBoundary(t *testing.T) {', '\nfunc runControllerNativeComfyBoundary');
  const comfyBoundary = section(apiTests, 'func runControllerNativeComfyBoundary(t *testing.T) {', '\nfunc runSignedOfflineBoundary');
  const offlineBoundary = section(apiTests, 'func runSignedOfflineBoundary(t *testing.T) {', '\nfunc runControllerResidencyQueryIntegration');
  const queryIntegration = section(apiTests, 'func runControllerResidencyQueryIntegration(t *testing.T) {', '\nfunc TestControllerNativeComfyBoundaryIsFailClosed');
  const comfyBoundaryTest = section(apiTests, 'func TestControllerNativeComfyBoundaryIsFailClosed(t *testing.T) {', '\nfunc ');
  if (!linuxBoundary || !/func TestControllerResidencySignedNodeBoundary\(t \*testing\.T\)\s*\{\s*runControllerResidencySignedNodeBoundary\(t\)/.test(linuxBoundary)) {
    issues.push('Linux signed boundary wrapper is missing its real helper call');
  }
  if (/func\s+TestControllerResidencySignedNodeBoundary\s*\(/.test(apiTests) || (linuxBoundary.match(/func\s+TestControllerResidencySignedNodeBoundary\s*\(/g) || []).length !== 1) {
    issues.push('signed controller/node boundary must have only the Linux wrapper test declaration');
  }
  if (!signedBoundary.includes('runSignedNodeLifecycleBoundary(t)') || !signedBoundary.includes('runSignedControllerWebsocketBoundary(t)') || !signedBoundary.includes('runSignedNodeRecoveryBoundary(t)') || !signedBoundary.includes('runSignedOfflineBoundary(t)') || !signedBoundary.includes('runControllerResidencyQueryIntegration(t)')) {
    issues.push('signed controller/node helper is a stub or omits a required real fixture component');
  }
  if (!lifecycleBoundary.includes('nodeagent.NewCommandHandler') || !apiTests.includes('wsproto.SignCommand(*command, secret)') || !lifecycleBoundary.includes('warm_model_bytes_verified')) {
    issues.push('signed node lifecycle boundary does not use the real command processor and verified warm proof');
  }
  if ((signedWarmFixture.match(/PressurePath:\s*"\/proc\/pressure\/memory"/g) || []).length !== 1 ||
      (signedWarmFixture.match(/PressureRefusalPercent:\s*100\b/g) || []).length !== 1) {
    issues.push('signed warm fixture lacks the real Linux PSI pressure source or its enabled refusal guard');
  }
  const restartSnapshotLoads = lifecycleBoundary.indexOf('beforeRestartLoads := node.runtime.loadCalls.Load()');
  const restartSnapshotUnloads = lifecycleBoundary.indexOf('beforeRestartUnloads := node.runtime.unloadCalls.Load()');
  const cleanupEvent = lifecycleBoundary.indexOf('boundaryEvent(t, "cleanup_cold")');
  const restartConstructor = lifecycleBoundary.indexOf('restarted := nodeagent.NewCommandHandler(');
  const restartReplayCall = lifecycleBoundary.indexOf('restartReplay := restarted.Handle(context.Background(), cleanup)');
  const restartControlCall = lifecycleBoundary.indexOf('assertSignedBoundaryCommandResultComparatorControls(t, cleaned)');
  const restartReplayEvent = lifecycleBoundary.indexOf('boundaryEvent(t, "restart_replay_exact")');
  const restartLoadAssertion = lifecycleBoundary.indexOf('node.runtime.loadCalls.Load() != beforeRestartLoads');
  const restartUnloadAssertion = lifecycleBoundary.indexOf('node.runtime.unloadCalls.Load() != beforeRestartUnloads');
  const comparatorMarshalErrorGuards = (restartResultComparator.match(/if err != nil \{\s*return false\s*\}/g) || []).length;
  const comparatorPositiveRoundTrip = restartComparatorControls.indexOf('if !signedBoundaryCommandResultJSONEqual(original, roundTrip)');
  const comparatorFirstNegative = restartComparatorControls.indexOf('reject("OK"');
  if (!restartResultComparator.includes('(before, after wsproto.CommandResultPayload)') ||
      !restartResultComparator.includes('before.CompletedAt.IsZero()') || !restartResultComparator.includes('after.CompletedAt.IsZero()') ||
      !restartResultComparator.includes('before.CompletedAt.Equal(after.CompletedAt)') || !restartResultComparator.includes('before.ID != after.ID') ||
      !restartResultComparator.includes('before.NodeID != after.NodeID') || !restartResultComparator.includes('before.Status != after.Status') ||
      !restartResultComparator.includes('before.Error != after.Error') || !restartResultComparator.includes('!before.OK') ||
      !restartResultComparator.includes('!after.OK') || !restartResultComparator.includes('before.Uncertain || after.Uncertain') ||
      !restartResultComparator.includes('json.Marshal(before)') || !restartResultComparator.includes('json.Marshal(after)') ||
      comparatorMarshalErrorGuards !== 2 || !restartResultComparator.includes('bytes.Equal(beforeJSON, afterJSON)') ||
      !lifecycleBoundary.includes('signedBoundaryCommandResultJSONEqual(cleaned, restartReplay)') ||
      cleanupEvent < 0 || restartSnapshotLoads <= cleanupEvent || restartSnapshotUnloads <= restartSnapshotLoads || restartConstructor <= restartSnapshotUnloads ||
      !/beforeRestartLoads := node\.runtime\.loadCalls\.Load\(\)\s+beforeRestartUnloads := node\.runtime\.unloadCalls\.Load\(\)\s+restarted := nodeagent\.NewCommandHandler\(/.test(lifecycleBoundary) ||
      restartReplayCall <= restartConstructor || restartLoadAssertion <= restartReplayCall || restartUnloadAssertion <= restartReplayCall ||
      restartControlCall <= restartReplayCall || restartReplayEvent <= restartControlCall ||
      !lifecycleBoundary.includes('node.runtime.currentState() != "unloaded"') ||
      !lifecycleBoundary.includes('restartReplay.Result["tier"] != "cold_disk"') ||
      !lifecycleBoundary.includes('restartReplay.Result["warm_ram"] != false') ||
      !lifecycleBoundary.includes('restartReplay.Result["cleaned"] != true') ||
      !lifecycleBoundary.includes('restartReplay.Result["warm_entry_absent"] != true') ||
      !lifecycleBoundary.includes('restartReplay.Result["warm_release_verified"] != true') ||
      !lifecycleBoundary.includes('restartReplay.Result["warm_model_bytes"] != float64(0)') ||
      !lifecycleBoundary.includes('restartReplay.Result["locked_bytes"] != float64(0)')) {
    issues.push('signed restart replay lacks complete checked JSON wire equality, explicit identity/time/success guards, or unchanged unloaded cleanup evidence');
  }
  const requiredComparatorMutations = [
    'complete cleanup payload JSON round-trip did not compare equal', 'original.Result["locked_bytes"].(int64)',
    'original.Result["warm_model_bytes"].(int64)', 'roundTrip.Result["locked_bytes"].(float64)',
    'roundTrip.Result["warm_model_bytes"].(float64)', 'reject("OK"', 'reject("uncertainty"', 'reject("ID"',
    'reject("NodeID"', 'reject("status"', 'reject("error"', 'reject("completion timestamp"',
    'reject("numeric value"', 'reject("numeric string type"', 'reject("numeric boolean type"',
    'reject("missing result key"', 'reject("extra result key"', 'reject("action"', 'reject("fingerprint"',
    'reject("fence value"', 'reject("observed fence value"', 'reject("marshal error"', 'candidate.Result = make(map[string]any',
    'bytes.Equal(originalJSON, afterControls)', '"action"', '"fingerprint"', '"fencing_token"', '"observed_after_fence"',
  ];
  if (!lifecycleBoundary.includes('assertSignedBoundaryCommandResultComparatorControls(t, cleaned)') ||
      requiredComparatorMutations.some((token) => !restartComparatorControls.includes(token)) ||
      comparatorPositiveRoundTrip < 0 || comparatorFirstNegative <= comparatorPositiveRoundTrip) {
    issues.push('signed restart JSON comparator controls lack a known-positive round-trip, complete value/type/schema negatives, marshal-error rejection, or original-map immutability proof');
  }
  if (!websocketBoundary.includes('websocket.Dial') || !websocketBoundary.includes('wsproto.MsgRegister') || !websocketBoundary.includes('wsproto.MsgCommandResult') || !websocketBoundary.includes('wsproto.VerifyCommand') || !websocketBoundary.includes('domain.NodeCommandSucceeded')) {
    issues.push('controller/node websocket boundary lacks registration, signed command, node result, and settled-success assertions');
  }
  if (!recoveryBoundary.includes('nodeagent.NewCommandHandler') || !recoveryBoundary.includes('wrongTargetResult.OK') || !recoveryBoundary.includes('wrongIdentityResult.OK') || !recoveryBoundary.includes('observed.Result["original_command_id"]') || !recoveryBoundary.includes('uncertain_restart_query_first')) {
    issues.push('uncertain node restart lacks wrong-resource/runtime rejection and exact query-first reconciliation assertions');
  }
  if (!rollbackBoundary.includes('inverse state restored') || !rollbackBoundary.includes('reconciliation required') || !rollbackBoundary.includes('mismatch_rollback_observed')) {
    issues.push('node rollback boundary lacks both observed inverse restoration and mismatched rollback refusal');
  }
  if (!offlineBoundary.includes('srv.sendNodeCommand') || !offlineBoundary.includes('domain.NodeCommandQueued') || !offlineBoundary.includes('offline_rejected')) {
    issues.push('offline node delivery lacks a durable no-dispatch assertion');
  }
  if (!comfyBoundary.includes('if target.SupportsAcceleratorReclaim {') || !comfyBoundary.includes('manager.DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")') || !comfyBoundary.includes('drainResult == nil || len(drainResult.TransitionIDs) != 0') || !comfyBoundary.includes('freeCalls.Load() != 0') || !comfyBoundaryTest.includes('runControllerNativeComfyBoundary(t)')) {
    issues.push('native Comfy controller reclaim attempt is not denied before transition with zero /free calls');
  }
  if (!queryIntegration.includes('TestControllerRejectsForgedAuthoritativeObservation') || !queryIntegration.includes('TestAdminNodeCommandUncertainReplayUsesQueryRecovery') || !signedBoundary.includes('runControllerResidencyQueryIntegration(t)')) {
    issues.push('signed boundary omits the uniquely named controller late-result/restart-query integration helper');
  }
  for (const event of ['load_hot', 'unload_cold', 'warm_verified', 'warm_replay_exact', 'cleanup_cold', 'late_result_reconciled', 'restart_replay_exact', 'node_handle_replay_exact', 'controller_restart_replay_exact', 'signed_expiry_zero_mutation', 'uncertain_restart_query_first', 'uncertain_intent_reconciled', 'live_pending_wrong_resource_rejected', 'live_pending_runtime_identity_rejected', 'stale_rejected', 'envelope_rejected', 'empty_capability_rejected', 'query_authoritative', 'rollback_observed', 'mismatch_rollback_observed', 'offline_rejected']) {
    if (!apiTests.includes(`boundaryEvent(t, '${event}')`) && !apiTests.includes(`boundaryEvent(t, "${event}")`) && !queryIntegration.includes(`"${event}"`)) {
      issues.push(`signed controller/node boundary lacks conditionally observed event ${event}`);
    }
  }
  const nativeComfyMeasuredChecks = Math.max(
    comfyBoundary.indexOf('manager.DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")'),
    comfyBoundary.indexOf('if (drainErr != nil || drainResult == nil || len(drainResult.TransitionIDs) != 0)'),
    comfyBoundary.indexOf('if target.SupportsAcceleratorReclaim || freeCalls.Load() != 0'),
  );
  const nativeComfyNewMarker = comfyBoundary.indexOf('boundaryEvent(t, "native_comfy_reclaim_denied_zero_free")');
  const nativeComfyLegacyMarker = comfyBoundary.indexOf('boundaryEvent(t, "native_comfy_capability_false_zero_free")');
  if (nativeComfyNewMarker <= nativeComfyMeasuredChecks || nativeComfyLegacyMarker <= nativeComfyMeasuredChecks) {
    issues.push('native Comfy denial markers are missing or precede the measured zero-free denial assertions');
  }
  if (!websocketBoundary.includes('node.runtime.currentState() != "loaded"') || !websocketBoundary.includes('node.runtime.loadCalls.Load() != beforeLoadCalls+1') || !websocketBoundary.includes('node.runtime.currentState() != "unloaded"') || !websocketBoundary.includes('node.runtime.unloadCalls.Load() != beforeUnloadCalls+1')) {
    issues.push('controller load/unload markers lack exact runtime-state and HTTP side-effect evidence');
  }
  if (!lifecycleBoundary.includes('beforeWarmReplayUnloads := node.runtime.unloadCalls.Load()') || !lifecycleBoundary.includes('node.runtime.unloadCalls.Load() != beforeWarmReplayUnloads')) {
    issues.push('warm replay marker lacks exact before/after mutation equality');
  }
  if (websocketBoundary.indexOf('node.runtime.currentState() != "loaded"') > websocketBoundary.indexOf('boundaryEvent(t, "load_hot")') || websocketBoundary.indexOf('node.runtime.currentState() != "unloaded"') > websocketBoundary.indexOf('boundaryEvent(t, "unload_cold")')) {
    issues.push('controller load/unload markers precede runtime-state and HTTP side-effect assertions');
  }
  for (const [event, anchor] of [
    ['load_hot', 'node.runtime.loadCalls.Load() != beforeLoadCalls+1'],
    ['unload_cold', 'node.runtime.unloadCalls.Load() != beforeUnloadCalls+1'],
    ['warm_verified', 'warmed.Result["warm_model_bytes_verified"] != true'],
    ['warm_replay_exact', 'node.runtime.unloadCalls.Load() != beforeWarmReplayUnloads'],
    ['cleanup_cold', 'cleaned.Result["warm_release_verified"] != true'],
    ['node_handle_replay_exact', 'replayedLoad.CompletedAt != loaded.CompletedAt'],
    ['restart_replay_exact', '!signedBoundaryCommandResultJSONEqual(cleaned, restartReplay)'],
    ['signed_expiry_zero_mutation', 'mutationCount != node.runtime.loadCalls.Load()+node.runtime.unloadCalls.Load()'],
    ['stale_rejected', 'staleResult.OK || !strings.Contains(staleResult.Error, "stale")'],
    ['envelope_rejected', 'envelopeResult.OK || node.runtime.loadCalls.Load() != beforeEnvelope'],
    ['empty_capability_rejected', 'emptyResult.OK || node.runtime.loadCalls.Load() != beforeEmpty'],
    ['rollback_observed', 'rolledBack.OK || !rolledBack.Uncertain'],
    ['mismatch_rollback_observed', 'mismatchResult.OK || !mismatchResult.Uncertain'],
    ['offline_rejected', 'after.Status != domain.NodeCommandQueued || after.Attempts != 0'],
    ['controller_restart_replay_exact', 'replayed.ID != unloaded.ID || replayed.Status != domain.NodeCommandSucceeded || replayed.Signature != unloaded.Signature || !bytes.Equal(replayed.Result, unloaded.Result)'],
    ['uncertain_restart_query_first', 'node.runtime.loadCalls.Load() != 1'],
    ['live_pending_wrong_resource_rejected', 'wrongTargetResult.OK || !strings.Contains(wrongTargetResult.Error, "target")'],
    ['live_pending_runtime_identity_rejected', 'wrongIdentityResult.OK || !strings.Contains(wrongIdentityResult.Error, "runtime")'],
    ['query_authoritative', '!observed.OK || observed.Result["tier"] != "cold_disk"'],
    ['uncertain_intent_reconciled', 'replay := restarted.Handle(context.Background(), query)'],
  ]) {
    if (!apiTests.includes(anchor)) issues.push(`event ${event} lacks its substantive Go assertion`);
    const eventLiteral = `boundaryEvent(t, "${event}")`;
    const eventPosition = apiTests.indexOf(eventLiteral);
    const assertionPosition = apiTests.indexOf(anchor);
    if (eventPosition >= 0 && (assertionPosition < 0 || assertionPosition > eventPosition)) {
      issues.push(`event ${event} is logged before its substantive Go assertion`);
    }
  }
  for (const [event, anchor] of [
    ['late_result_reconciled', 'settledOriginal.Status != domain.NodeCommandSucceeded'],
    ['live_pending_wrong_resource_rejected', '{name: "target-id"'],
    ['live_pending_runtime_identity_rejected', '{name: "runtime"'],
    ['query_authoritative', 'valid authoritative result did not settle pending original'],
    ['controller_restart_replay_exact', 'replayed.ID != original.ID || !replayed.Uncertain || replayed.Status != domain.NodeCommandSent || replayed.Attempts != original.Attempts'],
  ]) {
    if (!workloadTests.includes(anchor)) issues.push(`controller query event ${event} lacks its underlying API integration assertion`);
  }
  if (queryIntegration.indexOf('if !t.Run("uncertain-controller-query"') < 0 || queryIntegration.indexOf('for _, event := range []string{"late_result_reconciled"') < queryIntegration.indexOf('if !t.Run("uncertain-controller-query"')) {
    issues.push('controller query event markers are not gated on the real forged-observation integration test');
  }
  for (const sourcePath of ['internal/api/ws.go', 'internal/api/ws_test.go']) {
    if (!sources[sourcePath]) issues.push(`owned API registration source is unavailable: ${sourcePath}`);
  }
  return issues;
}

function loadSources() {
  const sources = Object.fromEntries(owned.map((relative) => [relative, readOwned(relative)]));
  // These two test files are read-only dependencies of the Linux boundary
  // gate. They remain outside this verifier's owned source set and are never
  // edited by this repair.
  for (const relative of ['internal/api/node_commands_linux_test.go', 'internal/api/workloads_http_test.go']) {
    const filename = path.join(root, relative);
    if (!existsSync(filename)) throw new Error(`read-only signed boundary source is missing: ${relative}`);
    sources[relative] = readFileSync(filename, 'utf8');
  }
  return sources;
}

const FAILURE_DIAGNOSTIC_HEADER = 'FAILURE-ONLY Go test diagnostic: closed reason and expected test IDs; event output suppressed\n';
const FAILURE_DIAGNOSTIC_MAX_BYTES = 2 * 1024 * 1024;
const FAILURE_DIAGNOSTIC_MAX_EVENTS = 10000;
const FAILURE_DIAGNOSTIC_MAX_LINE_BYTES = 64 * 1024;
const FAILURE_DIAGNOSTIC_MAX_IDS = 32;
const FAILURE_DIAGNOSTIC_MAX_ID_LENGTH = 180;
const FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES = 6144;
const GO_EVENT_ACTIONS = new Set(['start', 'run', 'pass', 'fail', 'skip', 'output', 'pause', 'cont']);
const GO_EVENT_KEYS = new Set(['Package', 'Action', 'Test', 'Output', 'Elapsed', 'Time']);
const ZERO_CONTEXT_DIAGNOSTIC_PACKAGE = 'vram-governor/internal/workloads';
const ZERO_CONTEXT_DIAGNOSTIC_TEST = 'TestRuntimeProfileZeroContextAdmissionCannotMutatePendingGeneration';
const ZERO_CONTEXT_DIAGNOSTIC_SITE_COUNT = 8;
const ZERO_CONTEXT_DIAGNOSTIC_SITE_ENUMS = new Set([
  'fixture_precondition', 'pending_install', 'residency_seed', 'submit', 'post_admit_assertion',
]);
const HIGH_WATER_DIAGNOSTIC_PACKAGE = 'vram-governor/internal/api';
const HIGH_WATER_DIAGNOSTIC_TEST = 'TestRuntimeProfileProjectionBeforeWaiterAdmission/residency_high-water_writer_waits_for_result_projection';
const HIGH_WATER_DIAGNOSTIC_SITE_ENUMS = new Set([
  'dispatch', 'result_cas_entry', 'pending_capacity', 'residency_seed', 'snapshot_entry',
  'result_projection', 'stale_writer_error', 'stale_writer_join', 'stale_row',
  'fresh_writer_error', 'fresh_row', 'submit', 'worker_join', 'final_admission',
]);
const HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS = Object.freeze([
  ['t.Fatal("scheduler did not dispatch the profile command")', 'dispatch'],
  ['t.Fatal("result handler did not reach the durable success CAS barrier")', 'result_cas_entry'],
  ['t.Fatalf("profile transition was not pending at the success CAS barrier:', 'pending_capacity'],
  ['t.Fatal(upsertErr)', 'residency_seed'],
  ['t.Fatal("ConfigureResidency did not capture its target/generation snapshot before the store barrier")', 'snapshot_entry'],
  ['t.Fatalf("residency high-water writer changed pending capacity during success CAS:', 'pending_capacity'],
  ['t.Fatal("result CAS/projection did not finish after releasing its barrier")', 'result_projection'],
  ['t.Fatalf("writer using its preprojection snapshot did not fail closed:', 'stale_writer_error'],
  ['t.Fatal("stale residency writer did not finish after releasing the snapshot barrier")', 'stale_writer_join'],
  ['t.Fatalf("stale writer changed durable high-water state:', 'stale_row'],
  ['t.Fatalf("new writer snapshot after result projection did not recover settled high-water:', 'fresh_writer_error'],
  ['t.Fatalf("fresh settled writer did not advance durable generation once:', 'fresh_row'],
  ['t.Fatalf("asynchronous barrier Submit failed after result projection:', 'submit'],
  ['t.Fatal("asynchronous barrier Submit did not return after result projection")', 'submit'],
  ['t.Fatal("asynchronous barrier Submit goroutine did not join")', 'worker_join'],
  ['t.Fatal("barrier workers did not settle before manager/server cleanup")', 'worker_join'],
  ['t.Fatalf("workload did not reach admission after observed projection:', 'final_admission'],
  ['t.Fatalf("admission did not use the observed profile capacity:', 'final_admission'],
]);
const GO_FAILURE_REASONS = Object.freeze({
  packageFail: 'package_fail',
  namedTestFailure: 'named_test_failure',
  missingPackagePass: 'missing_package_pass',
  missingExactInventory: 'missing_exact_inventory',
  nonzeroWithoutNamedFailure: 'nonzero_status_without_named_failure',
  malformedOrUnexpected: 'malformed_or_unexpected_event',
});
const GO_CRASH_ENUMS = Object.freeze({ timeout: 'timeout', deadlock: 'deadlock', panic: 'panic', buildError: 'build_error', unknown: 'unknown' });
const FAILURE_DIAGNOSTIC_SOURCE_FILES = Object.freeze({
  'vram-governor/internal/api': [
    'internal/api/node_commands.go', 'internal/api/node_commands_test.go', 'internal/api/ws.go', 'internal/api/ws_test.go',
  ],
  'vram-governor/internal/workloads': [
    'internal/workloads/manager.go', 'internal/workloads/manager_test.go', 'internal/workloads/residency.go',
  ],
});

function classifyPrivateGoCrash(outputChunks, stderr, pkg) {
  const texts = [...outputChunks, stderr];
  const lines = texts.flatMap((chunk) => chunk.split(/\r?\n/));
  if (lines.length > FAILURE_DIAGNOSTIC_MAX_EVENTS || lines.some((line) => Buffer.byteLength(line, 'utf8') > FAILURE_DIAGNOSTIC_MAX_LINE_BYTES)) return null;
  const joined = lines.join('\n');
  let crash = GO_CRASH_ENUMS.unknown;
  if (/^(?:panic:\s*test timed out after\b|test timed out after\b|panic: test timed out waiting for\b)/im.test(joined)) {
    crash = GO_CRASH_ENUMS.timeout;
  } else if (/^fatal error:\s*all goroutines are asleep - deadlock!\s*$/im.test(joined)) {
    crash = GO_CRASH_ENUMS.deadlock;
  } else if (/^(?:panic:|fatal error:|runtime error:)/im.test(joined)) {
    crash = GO_CRASH_ENUMS.panic;
  } else if (/^#\s+vram-governor\/internal\/(?:api|workloads)\s*$/m.test(joined) ||
      /^FAIL\s+vram-governor\/internal\/(?:api|workloads)\s+\[build failed\]\s*$/m.test(joined)) {
    crash = GO_CRASH_ENUMS.buildError;
  }

  const locations = new Set();
  for (const file of FAILURE_DIAGNOSTIC_SOURCE_FILES[pkg] || []) {
    const escaped = file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`(?:^|[/\\\\])${escaped}:(\\d{1,7})(?::\\d+)?(?=$|[\\s+:])`, 'gm');
    for (const match of joined.matchAll(pattern)) {
      const line = Number(match[1]);
      if (Number.isSafeInteger(line) && line > 0 && line <= 1_000_000) locations.add(`${file}:${line}`);
      if (locations.size >= 4) break;
    }
    if (locations.size >= 4) break;
  }
  return { crash, locations: [...locations] };
}

function zeroContextFailureSites(managerTests) {
  const testStart = managerTests.indexOf(`func ${ZERO_CONTEXT_DIAGNOSTIC_TEST}(t *testing.T) {`);
  if (testStart < 0) throw new Error('zero-context diagnostic source test is missing');
  const testSource = section(managerTests, `func ${ZERO_CONTEXT_DIAGNOSTIC_TEST}(t *testing.T) {`, '\nfunc ');
  const absoluteStart = managerTests.indexOf(testSource, testStart);
  const lineAt = (position) => managerTests.slice(0, absoluteStart + position).split('\n').length;
  const sites = new Map();
  const add = (position, site) => {
    if (position < 0) throw new Error(`zero-context diagnostic source site is missing: ${site}`);
    const line = lineAt(position);
    if (sites.has(line)) throw new Error('zero-context diagnostic source sites are ambiguous');
    sites.set(line, site);
  };
  const fatalAfter = (anchor, fatalLine, site) => {
    const from = testSource.indexOf(anchor);
    const fatal = from < 0 ? -1 : testSource.indexOf(fatalLine, from + anchor.length);
    if (fatal < 0 || testSource.indexOf('\n\t}', fatal) < 0 ||
        testSource.indexOf('\n\t}', fatal) < testSource.indexOf('\n\tt.Fatal', fatal)) {
      throw new Error(`zero-context diagnostic source block is ambiguous: ${site}`);
    }
    add(fatal, site);
  };

  add(testSource.indexOf('\t\tt.Fatal("zero-context fixture must begin with the model not resident")'), 'fixture_precondition');
  add(testSource.indexOf('\t\tt.Fatalf("read registered cold residency seed: %v", err)'), 'fixture_precondition');
  add(testSource.indexOf('\t\tt.Fatal("registered cold residency seed did not match the canonical target fence")'), 'fixture_precondition');
  fatalAfter('if _, _, err := manager.beginRuntimeProfileTransition(', '\t\tt.Fatal(err)', 'pending_install');
  fatalAfter('seededResidency, err := manager.store.UpsertModelResidency(', '\t\tt.Fatalf("seed durable HOT residency: %v", err)', 'residency_seed');
  add(testSource.indexOf('\t\tt.Fatal("durable HOT residency seed did not retain its canonical fence")'), 'residency_seed');
  const submit = testSource.indexOf('workload, _, err := manager.Submit(');
  const submitFatal = submit < 0 ? -1 : testSource.indexOf('\t\tt.Fatal(err)', submit);
  if (submit < 0 || submitFatal < 0 || testSource.indexOf('\n\t}', submitFatal) < 0 ||
      testSource.indexOf('\n\t}', submitFatal) < testSource.indexOf('\n\tt.Fatal', submitFatal)) {
    throw new Error('zero-context diagnostic submit source block is ambiguous');
  }
  add(submitFatal, 'submit');
  add(testSource.indexOf('\t\tt.Fatalf("zero-context HOT reconciliation mutated a pending profile generation:'), 'post_admit_assertion');
  if (sites.size !== ZERO_CONTEXT_DIAGNOSTIC_SITE_COUNT) throw new Error('zero-context diagnostic source inventory is incomplete');
  return sites;
}

function highWaterFailureSites(apiTests, anchors = HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS) {
  const testStart = apiTests.indexOf('func TestRuntimeProfileProjectionBeforeWaiterAdmission(t *testing.T) {');
  if (testStart < 0) throw new Error('high-water diagnostic API source test is missing');
  const testSource = section(apiTests, 'func TestRuntimeProfileProjectionBeforeWaiterAdmission(t *testing.T) {', '\nfunc ');
  const absoluteStart = apiTests.indexOf(testSource, testStart);
  const lineAt = (position) => apiTests.slice(0, absoluteStart + position).split('\n').length;
  const caseAnchor = '{name: "residency high-water writer waits for result projection", resultCASLifecycleBarrier: true, residencyWriterCASBarrier: true}';
  if (testSource.split(caseAnchor).length - 1 !== 1 || !testSource.includes('t.Run(testCase.name, func(t *testing.T)')) {
    throw new Error('high-water diagnostic test identity is missing or ambiguous');
  }
  const sites = new Map();
  for (const [anchor, site] of anchors) {
    const first = testSource.indexOf(anchor);
    if (first < 0 || testSource.indexOf(anchor, first + anchor.length) >= 0) {
      throw new Error(`high-water diagnostic source anchor is missing or ambiguous: ${site}`);
    }
    const line = lineAt(first);
    if (!Number.isSafeInteger(line) || line < 1 || line > apiTests.split('\n').length || sites.has(line) ||
        !HIGH_WATER_DIAGNOSTIC_SITE_ENUMS.has(site)) {
      throw new Error('high-water diagnostic source map is colliding or out of bounds');
    }
    sites.set(line, site);
  }
  if (HIGH_WATER_DIAGNOSTIC_SITE_ENUMS.size !== 14 ||
      [...HIGH_WATER_DIAGNOSTIC_SITE_ENUMS].some((site) => ![...sites.values()].includes(site)) ||
      sites.size !== anchors.length) throw new Error('high-water diagnostic source inventory is incomplete');
  Object.defineProperties(sites, {
    sourcePath: { value: 'internal/api/node_commands_test.go' },
    testName: { value: HIGH_WATER_DIAGNOSTIC_TEST },
    sourceLineCount: { value: apiTests.split('\n').length },
  });
  return sites;
}

function validHighWaterFailureSites(sites) {
  return sites instanceof Map && sites.size === HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS.length &&
    sites.sourcePath === 'internal/api/node_commands_test.go' && sites.testName === HIGH_WATER_DIAGNOSTIC_TEST &&
    Number.isSafeInteger(sites.sourceLineCount) && sites.sourceLineCount > 0 &&
    [...sites].every(([line, site]) => Number.isSafeInteger(line) && line > 0 && line <= sites.sourceLineCount &&
      HIGH_WATER_DIAGNOSTIC_SITE_ENUMS.has(site)) &&
    [...HIGH_WATER_DIAGNOSTIC_SITE_ENUMS].every((site) => [...sites.values()].includes(site));
}

function failureOnlyGoTestDiagnostic(stdout, status, pkg, names, zeroContextSites, stderr = '', highWaterSites = null) {
  if (status === 0) return '';
  const unavailable = () => `${FAILURE_DIAGNOSTIC_HEADER}diagnostic unavailable\n`;
  if (typeof status !== 'number' || !Number.isInteger(status) || !Number.isSafeInteger(status) || status < 1 || status > 255 ||
      typeof stdout !== 'string' || typeof stderr !== 'string' || typeof pkg !== 'string' || pkg.length === 0 || pkg.length > 180 ||
      !(names instanceof Set) || names.size === 0 || names.size > 1000 ||
      !(zeroContextSites instanceof Map) || zeroContextSites.size !== ZERO_CONTEXT_DIAGNOSTIC_SITE_COUNT ||
      [...zeroContextSites.values()].some((site) => !ZERO_CONTEXT_DIAGNOSTIC_SITE_ENUMS.has(site)) ||
      Buffer.byteLength(stdout, 'utf8') + Buffer.byteLength(stderr, 'utf8') > FAILURE_DIAGNOSTIC_MAX_BYTES) return unavailable();
  if (names.has(ZERO_CONTEXT_DIAGNOSTIC_TEST) && pkg !== ZERO_CONTEXT_DIAGNOSTIC_PACKAGE) return unavailable();
  if (names.has(HIGH_WATER_DIAGNOSTIC_TEST) &&
      (pkg !== HIGH_WATER_DIAGNOSTIC_PACKAGE || !validHighWaterFailureSites(highWaterSites))) return unavailable();
  for (const name of names) {
    if (typeof name !== 'string' || name.length === 0 || name.length > FAILURE_DIAGNOSTIC_MAX_ID_LENGTH || !/^[A-Za-z0-9_./-]+$/.test(name)) return unavailable();
  }

  const failures = new Set();
  const zeroContextSiteReports = new Set();
  const highWaterSiteReports = new Set();
  const privateOutputs = [];
  const activeTests = new Set();
  let lastActive = '';
  const lines = stdout.split(/\r?\n/);
  if (lines.length > FAILURE_DIAGNOSTIC_MAX_EVENTS) return unavailable();
  const malformed = () => `${FAILURE_DIAGNOSTIC_HEADER}reason=${GO_FAILURE_REASONS.malformedOrUnexpected} status=${status}\n`;
  const seenRun = new Map([...names].map((name) => [name, 0]));
  const seenPass = new Map([...names].map((name) => [name, 0]));
  const paused = new Set();
  let eventCount = 0;
  let packageStarted = false;
  let packageTerminalSeen = false;
  let packagePass = 0;
  let packageFailed = false;
  let inventoryProblem = false;
  for (const line of lines) {
    if (!line) continue;
    eventCount += 1;
    if (eventCount > FAILURE_DIAGNOSTIC_MAX_EVENTS || Buffer.byteLength(line, 'utf8') > FAILURE_DIAGNOSTIC_MAX_LINE_BYTES) return unavailable();
    let event;
    try { event = JSON.parse(line); } catch { return malformed(); }
    if (!event || typeof event !== 'object' || Array.isArray(event) || Object.getPrototypeOf(event) !== Object.prototype ||
        Object.keys(event).some((key) => !GO_EVENT_KEYS.has(key)) || event.Package !== pkg ||
        typeof event.Action !== 'string' || !GO_EVENT_ACTIONS.has(event.Action)) return malformed();
    if (event.Test !== undefined && (typeof event.Test !== 'string' || event.Test.length === 0 ||
        event.Test.length > FAILURE_DIAGNOSTIC_MAX_ID_LENGTH || !names.has(event.Test))) return malformed();
    if (event.Output !== undefined && typeof event.Output !== 'string') return malformed();
    if (event.Action === 'output' && typeof event.Output !== 'string') return malformed();
    if (event.Output !== undefined) privateOutputs.push(event.Output);
    if (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0)) return malformed();
    if (event.Time !== undefined && (typeof event.Time !== 'string' || !Number.isFinite(Date.parse(event.Time)))) return malformed();

    if (event.Action === 'output' && event.Test === ZERO_CONTEXT_DIAGNOSTIC_TEST) {
      for (const outputLine of event.Output.split(/\r?\n/)) {
        if (!outputLine.includes('manager_test.go:')) continue;
        const match = /^[\t ]*manager_test\.go:(\d+): [^\r\n]*$/.exec(outputLine);
        if (!match) return unavailable();
        const site = zeroContextSites.get(Number(match[1]));
        if (!site) return unavailable();
        zeroContextSiteReports.add(`site ${ZERO_CONTEXT_DIAGNOSTIC_TEST} ${site}`);
      }
    }
    if (event.Action === 'output' && pkg === HIGH_WATER_DIAGNOSTIC_PACKAGE && event.Test === HIGH_WATER_DIAGNOSTIC_TEST) {
      for (const outputLine of event.Output.split(/\r?\n/)) {
        if (!outputLine.includes('node_commands_test.go:')) {
          if (event.Test === HIGH_WATER_DIAGNOSTIC_TEST && /^[\t ]*[^\t ]+\.go:\d+:/.test(outputLine)) return unavailable();
          continue;
        }
        const match = /^[\t ]*node_commands_test\.go:(\d+): [^\r\n]*$/.exec(outputLine);
        if (!match || !validHighWaterFailureSites(highWaterSites)) return unavailable();
        const site = highWaterSites.get(Number(match[1]));
        if (!site) return unavailable();
        highWaterSiteReports.add(`site ${HIGH_WATER_DIAGNOSTIC_TEST} ${site}`);
      }
    }

    if (event.Action === 'start') {
      if (packageStarted || event.Test !== undefined || event.Output !== undefined || event.Elapsed !== undefined) return malformed();
      packageStarted = true;
      continue;
    }
    if (!packageStarted || packageTerminalSeen) return malformed();
    if (event.Action === 'pass' && event.Test === undefined) {
      if (event.Output !== undefined) return malformed();
      packagePass += 1;
      if (packagePass !== 1) return malformed();
      packageTerminalSeen = true;
      continue;
    }
    if (event.Action === 'fail' && event.Test === undefined) {
      packageFailed = true;
      packageTerminalSeen = true;
      continue;
    }
    if (event.Action === 'skip' && event.Test === undefined) return malformed();
    if ((event.Action === 'fail' || event.Action === 'skip') && event.Test !== undefined) failures.add(`${event.Action} ${event.Test}`);
    if ((event.Action === 'fail' || event.Action === 'skip') && event.Test !== undefined) {
      activeTests.delete(event.Test);
      if (lastActive === event.Test) lastActive = [...activeTests].at(-1) || '';
    }
    if (event.Test === undefined) {
      if (event.Action !== 'output') return malformed();
      continue;
    }
    if (event.Action === 'run') {
      if (seenRun.get(event.Test) !== 0) inventoryProblem = true;
      const slash = event.Test.lastIndexOf('/');
      const parent = slash < 0 ? '' : event.Test.slice(0, slash);
      if (parent && (seenRun.get(parent) !== 1 || seenPass.get(parent) === 1)) inventoryProblem = true;
      seenRun.set(event.Test, seenRun.get(event.Test) + 1);
      activeTests.add(event.Test);
      lastActive = event.Test;
      continue;
    }
    if (seenRun.get(event.Test) !== 1 || seenPass.get(event.Test) !== 0) inventoryProblem = true;
    if (event.Action === 'output') continue;
    if (event.Action === 'pause') {
      if (paused.has(event.Test)) return malformed();
      paused.add(event.Test);
      continue;
    }
    if (event.Action === 'cont') {
      if (!paused.has(event.Test)) return malformed();
      paused.delete(event.Test);
      continue;
    }
    if (event.Action === 'pass') {
      if (paused.has(event.Test)) return malformed();
      if ([...names].some((name) => name.startsWith(`${event.Test}/`) && seenPass.get(name) !== 1)) inventoryProblem = true;
      seenPass.set(event.Test, seenPass.get(event.Test) + 1);
      activeTests.delete(event.Test);
      if (lastActive === event.Test) lastActive = [...activeTests].at(-1) || '';
    }
  }

  if (!packageStarted && eventCount > 0) return malformed();
  let reason;
  if (packageFailed) reason = GO_FAILURE_REASONS.packageFail;
  else if (failures.size > 0) reason = GO_FAILURE_REASONS.namedTestFailure;
  else if (packagePass === 0) reason = GO_FAILURE_REASONS.missingPackagePass;
  else if (inventoryProblem || paused.size > 0 || [...names].some((name) => seenRun.get(name) !== 1 || seenPass.get(name) !== 1)) {
    reason = GO_FAILURE_REASONS.missingExactInventory;
  } else reason = GO_FAILURE_REASONS.nonzeroWithoutNamedFailure;

  const crashInfo = classifyPrivateGoCrash(privateOutputs, stderr, pkg);
  if (!crashInfo) return unavailable();
  if (highWaterSiteReports.size > 0 &&
      (!failures.has(`fail ${HIGH_WATER_DIAGNOSTIC_TEST}`) || seenRun.get(HIGH_WATER_DIAGNOSTIC_TEST) !== 1 ||
       seenPass.get(HIGH_WATER_DIAGNOSTIC_TEST) !== 0)) return unavailable();
  const highWaterFailureReported = failures.has(`fail ${HIGH_WATER_DIAGNOSTIC_TEST}`) || highWaterSiteReports.size > 0;
  const safeCrashLocations = highWaterFailureReported
    ? crashInfo.locations.filter((location) => {
      const match = /^internal\/api\/node_commands_test\.go:(\d+)$/.exec(location);
      return !match || !highWaterSites.has(Number(match[1]));
    })
    : crashInfo.locations;
  const unfinished = [...names].filter((name) => seenPass.get(name) !== 1 &&
    !failures.has(`fail ${name}`) && !failures.has(`skip ${name}`));
  const ids = [
    ...failures,
    ...zeroContextSiteReports,
    ...highWaterSiteReports,
    ...(lastActive ? [`last_active ${lastActive}`] : []),
    ...safeCrashLocations.map((location) => `source ${location}`),
    ...unfinished.map((name) => `unfinished ${name}`),
  ];
  const observedRuns = [...seenRun.values()].reduce((total, count) => total + count, 0);
  const observedPasses = [...seenPass.values()].reduce((total, count) => total + count, 0);
  const progress = `expected_run=${names.size} expected_pass=${names.size} observed_run_events=${observedRuns} observed_pass_events=${observedPasses} last_active=${lastActive || 'none'} unfinished_expected=${unfinished.length} crash=${crashInfo.crash}\n`;
  let shownCount = Math.min(ids.length, FAILURE_DIAGNOSTIC_MAX_IDS);
  let diagnostic;
  do {
    const shown = ids.slice(0, shownCount).map((id) => `${id}\n`).join('');
    const omittedCount = Math.max(0, ids.length - shownCount);
    const remainder = omittedCount > 0 ? `additional diagnostic entries omitted: ${omittedCount}\n` : '';
    diagnostic = `${FAILURE_DIAGNOSTIC_HEADER}reason=${reason} status=${status}\n${progress}${shown}${remainder}`;
    if (Buffer.byteLength(diagnostic, 'utf8') <= FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) return diagnostic;
    shownCount -= 1;
  } while (shownCount > 0);
  return unavailable();
}

function parseGoTestStream(stdout, status, pkg, names) {
  const seenRun = new Map([...names].map((name) => [name, 0]));
  const seenPass = new Map([...names].map((name) => [name, 0]));
  const paused = new Set();
  let packagePass = 0;
  let packageStarted = false;
  let packageTerminalSeen = false;
  for (const line of stdout.split(/\r?\n/)) {
    if (!line) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error(`malformed Go JSON event for ${pkg}`); }
    if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error(`Go event is not an object for ${pkg}`);
    if (typeof event.Package !== 'string' || event.Package.length === 0) throw new Error(`Go event omitted package for ${pkg}`);
    if (event.Package !== pkg) throw new Error(`unexpected Go package event ${event.Package}; expected ${pkg}`);
    if (packageTerminalSeen) throw new Error(`Go emitted an event after package completion for ${pkg}`);
    for (const key of Object.keys(event)) {
      if (!['Package', 'Action', 'Test', 'Output', 'Elapsed', 'Time'].includes(key)) throw new Error(`unknown Go event field ${key} for ${pkg}`);
    }
    if (typeof event.Action !== 'string' || !['start', 'run', 'pass', 'fail', 'skip', 'output', 'pause', 'cont'].includes(event.Action)) {
      throw new Error(`unknown Go event action ${String(event.Action)} for ${pkg}`);
    }
    if (event.Test !== undefined && (typeof event.Test !== 'string' || event.Test.length === 0)) throw new Error(`invalid Go Test field for ${pkg}`);
    if (event.Output !== undefined && typeof event.Output !== 'string') throw new Error(`invalid Go Output field for ${pkg}`);
    if (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0)) throw new Error(`invalid Go Elapsed field for ${pkg}`);
    if (event.Time !== undefined && (typeof event.Time !== 'string' || !Number.isFinite(Date.parse(event.Time)))) throw new Error(`invalid Go Time field for ${pkg}`);
    if (event.Action === 'output' && typeof event.Output !== 'string') throw new Error(`Go output event omitted Output for ${pkg}`);

    if (event.Action === 'start') {
      if (packageStarted) throw new Error(`duplicate Go package start for ${pkg}`);
      if (event.Test !== undefined || event.Output !== undefined || event.Elapsed !== undefined) throw new Error(`malformed Go package start event for ${pkg}`);
      packageStarted = true;
      continue;
    }
    if (!packageStarted) throw new Error(`Go event preceded package start for ${pkg}`);

    if (event.Action === 'pass' && event.Test === undefined) {
      if (event.Output !== undefined) throw new Error(`malformed package PASS event for ${pkg}`);
      packagePass++;
      if (packagePass !== 1 || names.size === 0 || [...names].some((name) => seenRun.get(name) !== 1 || seenPass.get(name) !== 1) || paused.size > 0) {
        throw new Error(`Go package PASS preceded exact named RUN/PASS inventory for ${pkg}`);
      }
      packageTerminalSeen = true;
      continue;
    }
    if (event.Action === 'fail' || event.Action === 'skip') throw new Error(`Go ${event.Action} in ${pkg}${event.Test ? ` ${event.Test}` : ''}: ${event.Output || ''}`);
    if (event.Test === undefined) {
      if (event.Action !== 'output') throw new Error(`Go ${event.Action} event is missing Test for ${pkg}`);
      continue;
    }
    if (!names.has(event.Test)) throw new Error(`unexpected Go ${event.Action} event for ${pkg} ${event.Test}`);
    if (event.Action === 'run') {
      if (seenRun.get(event.Test) !== 0) throw new Error(`duplicate Go RUN event for ${pkg} ${event.Test}`);
      const slash = event.Test.lastIndexOf('/');
      const parent = slash < 0 ? '' : event.Test.slice(0, slash);
      if (parent && seenRun.get(parent) !== 1) throw new Error(`Go subtest ran before its parent for ${pkg} ${event.Test}`);
      if (parent && seenPass.get(parent) === 1) throw new Error(`Go subtest ran after parent PASS for ${pkg} ${event.Test}`);
      seenRun.set(event.Test, 1);
      continue;
    }
    if (seenRun.get(event.Test) !== 1 || seenPass.get(event.Test) === 1) throw new Error(`Go ${event.Action} event is outside the active RUN/PASS lifecycle for ${pkg} ${event.Test}`);
    if (event.Action === 'output') continue;
    if (event.Action === 'pause') {
      if (paused.has(event.Test)) throw new Error(`duplicate Go pause event for ${pkg} ${event.Test}`);
      paused.add(event.Test);
      continue;
    }
    if (event.Action === 'cont') {
      if (!paused.has(event.Test)) throw new Error(`Go cont event has no matching pause for ${pkg} ${event.Test}`);
      paused.delete(event.Test);
      continue;
    }
    if (event.Action === 'pass') {
      if (paused.has(event.Test)) throw new Error(`Go PASS occurred while test was paused for ${pkg} ${event.Test}`);
      const unpassedChild = [...names].find((name) => name.startsWith(`${event.Test}/`) && seenPass.get(name) !== 1);
      if (unpassedChild) throw new Error(`Go parent PASS preceded subtest PASS for ${pkg} ${unpassedChild}`);
      seenPass.set(event.Test, 1);
    }
  }
  if (status !== 0) throw new Error(`bounded Go test failed for ${pkg} with status ${status}`);
  if (packagePass !== 1) throw new Error(`expected exactly one package PASS for ${pkg}; PASS=${packagePass}`);
  for (const name of names) {
    if (seenRun.get(name) !== 1 || seenPass.get(name) !== 1) throw new Error(`expected exactly one RUN and PASS for ${pkg} ${name}; RUN=${seenRun.get(name)} PASS=${seenPass.get(name)}`);
  }
  return { packagePass, namedCount: names.size };
}

function testGoEventParserControls() {
  const pkg = 'fixture/pkg';
  const names = new Set(['TestOne', 'TestOne/sub_a']);
  const events = [
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'run', Test: 'TestOne' },
    { Package: pkg, Action: 'output', Test: 'TestOne', Output: '=== RUN   TestOne\\n' },
    { Package: pkg, Action: 'run', Test: 'TestOne/sub_a' },
    { Package: pkg, Action: 'pause', Test: 'TestOne/sub_a' },
    { Package: pkg, Action: 'cont', Test: 'TestOne/sub_a' },
    { Package: pkg, Action: 'output', Test: 'TestOne/sub_a', Output: 'subtest output\\n' },
    { Package: pkg, Action: 'pass', Test: 'TestOne/sub_a' },
    { Package: pkg, Action: 'pass', Test: 'TestOne' },
    { Package: pkg, Action: 'pass' },
  ];
  const encode = (values) => values.map((value) => typeof value === 'string' ? value : JSON.stringify(value)).join('\n');
  const positive = parseGoTestStream(encode(events), 0, pkg, names);
  if (positive.packagePass !== 1 || positive.namedCount !== 2) throw new Error('Go parser positive fixture produced incorrect counts');
  const rejects = (label, values, expected, status = 0, fixturePkg = pkg, fixtureNames = names) => {
    try { parseGoTestStream(encode(values), status, fixturePkg, fixtureNames); } catch (error) {
      if (!String(error.message).includes(expected)) throw new Error(`Go parser control ${label} failed for the wrong reason: ${error.message}`);
      return;
    }
    throw new Error(`Go parser negative fixture was accepted: ${label}`);
  };
  rejects('missing RUN', events.filter((event) => !(event.Action === 'run' && event.Test === 'TestOne')), 'outside the active RUN/PASS lifecycle');
  rejects('missing PASS', events.filter((event) => !(event.Action === 'pass' && event.Test === 'TestOne/sub_a')), 'parent PASS preceded subtest PASS');
  const parentRun = events.find((event) => event.Action === 'run' && event.Test === 'TestOne');
  rejects('duplicate RUN', [...events.slice(0, 2), parentRun, ...events.slice(2)], 'duplicate Go RUN');
  rejects('duplicate PASS', [...events.slice(0, -1), events.find((event) => event.Action === 'pass' && event.Test === 'TestOne/sub_a'), events.at(-1)], 'outside the active RUN/PASS');
  rejects('skip', [...events.slice(0, -1), { Package: pkg, Action: 'skip', Test: 'TestOne' }, events.at(-1)], 'Go skip');
  rejects('failure', [...events.slice(0, -1), { Package: pkg, Action: 'fail', Test: 'TestOne' }, events.at(-1)], 'Go fail');
  rejects('unexpected test', [...events.slice(0, -1), { Package: pkg, Action: 'run', Test: 'TestOther' }, events.at(-1)], 'unexpected Go run');
  rejects('unexpected package', [...events.slice(0, -1), { Package: 'fixture/other', Action: 'output', Test: 'TestOne', Output: 'x' }, events.at(-1)], 'unexpected Go package');
  rejects('malformed event', [...events, '{not-json'], 'malformed Go JSON');
  rejects('missing package completion', events.slice(0, -1), 'expected exactly one package PASS');
  rejects('nonzero terminal', events, 'bounded Go test failed', 1);
  rejects('missing package field', [...events.slice(0, 1), { Action: 'output', Test: 'TestOne', Output: 'x' }, ...events.slice(1)], 'omitted package');
  rejects('numeric package field', [...events.slice(0, 1), { Package: 7, Action: 'output', Test: 'TestOne', Output: 'x' }, ...events.slice(1)], 'omitted package');
  rejects('numeric Test field', [...events.slice(0, 1), { Package: pkg, Action: 'output', Test: 7, Output: 'x' }, ...events.slice(1)], 'invalid Go Test field');
  rejects('missing Action field', [...events.slice(0, 1), { Package: pkg, Test: 'TestOne' }, ...events.slice(1)], 'unknown Go event action');
  rejects('numeric Action field', [...events.slice(0, 1), { Package: pkg, Action: 7, Test: 'TestOne' }, ...events.slice(1)], 'unknown Go event action');
  rejects('unknown action', [...events.slice(0, -1), { Package: pkg, Action: 'warning', Test: 'TestOne' }, events.at(-1)], 'unknown Go event action');
  rejects('unknown output test', [...events.slice(0, -1), { Package: pkg, Action: 'output', Test: 'TestOne/output7', Output: 'x' }, events.at(-1)], 'unexpected Go output');
  rejects('output omitted', [...events.slice(0, 1), { Package: pkg, Action: 'output', Test: 'TestOne' }, ...events.slice(1)], 'omitted Output');
  rejects('cont without pause', [...events.slice(0, 4), { Package: pkg, Action: 'cont', Test: 'TestOne/sub_a' }, ...events.slice(6)], 'no matching pause');
  rejects('child RUN before parent', [events[0], events[3], events[1], ...events.slice(2)], 'ran before its parent');
  rejects('package PASS with Test field', [...events.slice(0, -1), { Package: pkg, Action: 'pass', Test: 'Test0' }], 'unexpected Go pass');
  rejects('empty inventory package PASS', [{ Package: pkg, Action: 'start' }, { Package: pkg, Action: 'pass' }], 'package PASS preceded exact named', 0, pkg, new Set());
  rejects('missing package start', events.slice(1), 'preceded package start');
  rejects('duplicate package start', [events[0], events[0], ...events.slice(1)], 'duplicate Go package start');
  rejects('package start after test', [events[1], events[0], ...events.slice(2)], 'preceded package start');
  rejects('skip after package PASS', [...events, { Package: pkg, Action: 'skip', Test: 'TestOne' }], 'after package completion');
  rejects('failure after package PASS', [...events, { Package: pkg, Action: 'fail', Test: 'TestOne' }], 'after package completion');
  rejects('unexpected event after package PASS', [...events, { Package: pkg, Action: 'run', Test: 'TestUnexpected' }], 'after package completion');
  console.log('SOURCEONLY: Go event parser positive and 29 reason-specific negative fixtures passed');
}

function testFailureOnlyGoTestDiagnosticControls(managerTests, apiTests) {
  const pkg = ZERO_CONTEXT_DIAGNOSTIC_PACKAGE;
  const names = new Set(['TestOne', 'TestOne/sub_a', ZERO_CONTEXT_DIAGNOSTIC_TEST]);
  const zeroContextSites = zeroContextFailureSites(managerTests);
  const highWaterSites = highWaterFailureSites(apiTests);
  const sourceSiteLines = [...zeroContextSites.keys()];
  if (sourceSiteLines.length !== ZERO_CONTEXT_DIAGNOSTIC_SITE_COUNT) throw new Error('zero-context diagnostic positive control has no complete source-site inventory');

  const highWaterNames = new Set([
    'TestRuntimeProfileProjectionBeforeWaiterAdmission',
    HIGH_WATER_DIAGNOSTIC_TEST,
  ]);
  const highWaterLine = [...highWaterSites.keys()][0];
  const highWaterEvents = [
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'start' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: HIGH_WATER_DIAGNOSTIC_TEST },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'output', Test: HIGH_WATER_DIAGNOSTIC_TEST, Output: `\tnode_commands_test.go:${highWaterLine}: hostile assertion value /private/path TOKEN=secret` },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail', Test: HIGH_WATER_DIAGNOSTIC_TEST, Output: 'raw assertion body must remain private' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail' },
  ];
  const encodeHighWater = (values) => values.map((value) => JSON.stringify(value)).join('\n');
  const highWaterDiagnostic = failureOnlyGoTestDiagnostic(
    encodeHighWater(highWaterEvents), 1, HIGH_WATER_DIAGNOSTIC_PACKAGE, highWaterNames, zeroContextSites, '', highWaterSites,
  );
  const mappedHighWaterSite = highWaterSites.get(highWaterLine);
  if (!highWaterDiagnostic.includes(`reason=${GO_FAILURE_REASONS.packageFail} status=1\n`) ||
      !highWaterDiagnostic.includes(`fail ${HIGH_WATER_DIAGNOSTIC_TEST}\n`) ||
      !highWaterDiagnostic.includes(`site ${HIGH_WATER_DIAGNOSTIC_TEST} ${mappedHighWaterSite}\n`) ||
      /hostile assertion|private\/path|TOKEN=secret|raw assertion body|node_commands_test\.go:\d+/.test(highWaterDiagnostic) ||
      Buffer.byteLength(highWaterDiagnostic, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('high-water failure diagnostic positive/privacy/source-enum control failed');
  }
  if (failureOnlyGoTestDiagnostic(encodeHighWater(highWaterEvents), 0, HIGH_WATER_DIAGNOSTIC_PACKAGE,
    highWaterNames, zeroContextSites, 'panic: keep silent', highWaterSites) !== '') {
    throw new Error('successful high-water test emitted failure diagnostics');
  }
  const highWaterUnavailable = `${FAILURE_DIAGNOSTIC_HEADER}diagnostic unavailable\n`;
  const wrongPackageHighWater = failureOnlyGoTestDiagnostic(encodeHighWater(highWaterEvents), 1,
    ZERO_CONTEXT_DIAGNOSTIC_PACKAGE, highWaterNames, zeroContextSites, '', highWaterSites);
  if (wrongPackageHighWater !== highWaterUnavailable) throw new Error('high-water diagnostic accepted wrong package identity');
  const wrongTestEvents = highWaterEvents.map((event) => ({ ...event }));
  const wrongTestOutput = wrongTestEvents.find((event) => event.Action === 'output');
  wrongTestOutput.Test = 'TestRuntimeProfileProjectionBeforeWaiterAdmission';
  const wrongTestDiagnostic = failureOnlyGoTestDiagnostic(encodeHighWater(wrongTestEvents), 1,
    HIGH_WATER_DIAGNOSTIC_PACKAGE, highWaterNames, zeroContextSites, '', highWaterSites);
  if (!wrongTestDiagnostic.includes(`reason=${GO_FAILURE_REASONS.packageFail} status=1\n`) ||
      !wrongTestDiagnostic.includes(`fail ${HIGH_WATER_DIAGNOSTIC_TEST}\n`) ||
      !wrongTestDiagnostic.includes('fail TestRuntimeProfileProjectionBeforeWaiterAdmission\n') ||
      wrongTestDiagnostic.includes(`site ${HIGH_WATER_DIAGNOSTIC_TEST} `) ||
      /hostile assertion|private\/path|TOKEN=secret|raw assertion body/.test(wrongTestDiagnostic)) {
    throw new Error('wrong-owner source output did not preserve repair25 generic failure fields without a high-water site enum');
  }
  const siblingFailureName = 'TestRuntimeProfileProjectionBeforeWaiterAdmission/registration_waits_for_durable_result_commit';
  const siblingNames = new Set([...highWaterNames, siblingFailureName]);
  const siblingEvents = [
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'start' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: siblingFailureName },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'output', Test: siblingFailureName, Output: `\tnode_commands_test.go:${highWaterLine}: hostile sibling assertion /private/path TOKEN=secret` },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail', Test: siblingFailureName, Output: 'raw sibling assertion body must stay private' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail' },
  ];
  const siblingDiagnostic = failureOnlyGoTestDiagnostic(encodeHighWater(siblingEvents), 1,
    HIGH_WATER_DIAGNOSTIC_PACKAGE, siblingNames, zeroContextSites, '', highWaterSites);
  // These are the finite generic failure fields retained by the repair25 classifier for this sibling.
  if (!siblingDiagnostic.includes(`reason=${GO_FAILURE_REASONS.packageFail} status=1\n`) ||
      !siblingDiagnostic.includes(`fail ${siblingFailureName}\n`) ||
      !siblingDiagnostic.includes('fail TestRuntimeProfileProjectionBeforeWaiterAdmission\n') ||
      siblingDiagnostic.includes(`site ${HIGH_WATER_DIAGNOSTIC_TEST} `) ||
      siblingDiagnostic.includes('diagnostic unavailable') ||
      /hostile sibling assertion|private\/path|TOKEN=secret|raw sibling assertion body|node_commands_test\.go:\d+/.test(siblingDiagnostic) ||
      Buffer.byteLength(siblingDiagnostic, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('shared-line sibling failure did not preserve repair25 generic diagnostics or emitted a high-water site enum');
  }
  const unrelatedCrashName = 'TestUnrelatedAPIWorkerCrash';
  const unrelatedCrashNames = new Set([...highWaterNames, unrelatedCrashName]);
  const unrelatedCrashEvents = [
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'start' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: HIGH_WATER_DIAGNOSTIC_TEST },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'pass', Test: HIGH_WATER_DIAGNOSTIC_TEST },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'pass', Test: 'TestRuntimeProfileProjectionBeforeWaiterAdmission' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'run', Test: unrelatedCrashName },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'output', Test: unrelatedCrashName, Output: 'panic: controlled unrelated API crash\n/tmp/private/internal/api/node_commands_test.go:1200 +0xSECRET' },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail', Test: unrelatedCrashName },
    { Package: HIGH_WATER_DIAGNOSTIC_PACKAGE, Action: 'fail' },
  ];
  const unrelatedCrashDiagnostic = failureOnlyGoTestDiagnostic(encodeHighWater(unrelatedCrashEvents), 1,
    HIGH_WATER_DIAGNOSTIC_PACKAGE, unrelatedCrashNames, zeroContextSites, '', highWaterSites);
  // Repair25 preserved this allowlisted location when an unrelated API test crashed; inventory alone must not suppress it.
  if (!unrelatedCrashDiagnostic.includes(`reason=${GO_FAILURE_REASONS.packageFail} status=1\n`) ||
      !unrelatedCrashDiagnostic.includes(`fail ${unrelatedCrashName}\n`) ||
      !unrelatedCrashDiagnostic.includes('crash=panic\n') ||
      !unrelatedCrashDiagnostic.includes('source internal/api/node_commands_test.go:1200\n') ||
      unrelatedCrashDiagnostic.includes(`site ${HIGH_WATER_DIAGNOSTIC_TEST} `) ||
      /controlled unrelated API crash|\/tmp\/private|SECRET/.test(unrelatedCrashDiagnostic) ||
      Buffer.byteLength(unrelatedCrashDiagnostic, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('unrelated API crash did not preserve repair25 allowlisted source metadata or leaked private text');
  }
  const wrongSourceEvents = highWaterEvents.map((event) => ({ ...event }));
  wrongSourceEvents.find((event) => event.Action === 'output').Output = '\tnode_commands_linux_test.go:11: hostile source';
  if (failureOnlyGoTestDiagnostic(encodeHighWater(wrongSourceEvents), 1, HIGH_WATER_DIAGNOSTIC_PACKAGE,
    highWaterNames, zeroContextSites, '', highWaterSites) !== highWaterUnavailable) throw new Error('high-water diagnostic accepted wrong source identity');
  const malformedSourceEvents = highWaterEvents.map((event) => ({ ...event }));
  malformedSourceEvents.find((event) => event.Action === 'output').Output = `node_commands_test.go:${highWaterLine}:missing-separator`;
  if (failureOnlyGoTestDiagnostic(encodeHighWater(malformedSourceEvents), 1, HIGH_WATER_DIAGNOSTIC_PACKAGE,
    highWaterNames, zeroContextSites, '', highWaterSites) !== highWaterUnavailable) throw new Error('high-water diagnostic accepted malformed source location');
  const unknownLineEvents = highWaterEvents.map((event) => ({ ...event }));
  unknownLineEvents.find((event) => event.Action === 'output').Output = `node_commands_test.go:${highWaterSites.sourceLineCount + 1}: unknown assertion`;
  if (failureOnlyGoTestDiagnostic(encodeHighWater(unknownLineEvents), 1, HIGH_WATER_DIAGNOSTIC_PACKAGE,
    highWaterNames, zeroContextSites, '', highWaterSites) !== highWaterUnavailable) throw new Error('high-water diagnostic accepted an out-of-bounds source line');
  const oversizedHighWaterEvents = highWaterEvents.map((event) => ({ ...event }));
  oversizedHighWaterEvents.find((event) => event.Action === 'output').Output = 'x'.repeat(FAILURE_DIAGNOSTIC_MAX_LINE_BYTES + 1);
  if (failureOnlyGoTestDiagnostic(encodeHighWater(oversizedHighWaterEvents), 1, HIGH_WATER_DIAGNOSTIC_PACKAGE,
    highWaterNames, zeroContextSites, '', highWaterSites) !== highWaterUnavailable) throw new Error('high-water diagnostic failed its output bounds');
  const badMap = new Map(highWaterSites);
  Object.defineProperties(badMap, {
    sourcePath: { value: highWaterSites.sourcePath }, testName: { value: highWaterSites.testName },
    sourceLineCount: { value: highWaterSites.sourceLineCount },
  });
  badMap.set(highWaterLine, 'private_assertion_text');
  if (validHighWaterFailureSites(badMap)) throw new Error('high-water diagnostic accepted a malformed site map');
  const outOfBoundsMap = new Map(highWaterSites);
  Object.defineProperties(outOfBoundsMap, {
    sourcePath: { value: highWaterSites.sourcePath }, testName: { value: highWaterSites.testName },
    sourceLineCount: { value: highWaterSites.sourceLineCount },
  });
  outOfBoundsMap.set(highWaterSites.sourceLineCount + 1, 'dispatch');
  if (validHighWaterFailureSites(outOfBoundsMap)) throw new Error('high-water diagnostic accepted an out-of-bounds site map');
  const wrongIdentityMap = new Map(highWaterSites);
  Object.defineProperties(wrongIdentityMap, {
    sourcePath: { value: 'internal/api/node_commands_linux_test.go' }, testName: { value: highWaterSites.testName },
    sourceLineCount: { value: highWaterSites.sourceLineCount },
  });
  if (validHighWaterFailureSites(wrongIdentityMap)) throw new Error('high-water diagnostic accepted a map from the wrong source');
  const firstAnchor = HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS[0];
  for (const [label, candidate, candidateAnchors] of [
    ['missing anchor', apiTests.replace(firstAnchor[0], 't.Fatal("removed dispatch assertion")'), HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS],
    ['duplicate anchor', apiTests.replace(firstAnchor[0], `${firstAnchor[0]}\n\t\t\t\t${firstAnchor[0]}`), HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS],
    ['colliding anchor map', apiTests, [...HIGH_WATER_DIAGNOSTIC_SITE_ANCHORS, firstAnchor]],
  ]) {
    try { highWaterFailureSites(candidate, candidateAnchors); } catch { continue; }
    throw new Error(`high-water diagnostic accepted ${label}`);
  }
  const events = [
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'fail', Test: 'TestOne', Output: 'secret stack and token must stay suppressed' },
    { Package: pkg, Action: 'skip', Test: 'TestOne/sub_a', Output: 'sensitive diagnostic body' },
    { Package: pkg, Action: 'fail', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST, Output: 'secret body must stay suppressed' },
    { Package: pkg, Action: 'output', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST, Output: sourceSiteLines.map((line) => `\tmanager_test.go:${line}: fixture details secret`).join('\n') + '\n' },
    { Package: pkg, Action: 'fail' },
  ];
  const encode = (values) => values.map((value) => typeof value === 'string' ? value : JSON.stringify(value)).join('\n');
  const positive = failureOnlyGoTestDiagnostic(encode(events), 1, pkg, names, zeroContextSites);
  if (!positive.startsWith(FAILURE_DIAGNOSTIC_HEADER) || !positive.includes('reason=package_fail status=1\n') ||
      !positive.includes('fail TestOne\n') || !positive.includes('skip TestOne/sub_a\n') ||
      [...zeroContextSites.values()].some((site) => !positive.includes(`site ${ZERO_CONTEXT_DIAGNOSTIC_TEST} ${site}\n`)) ||
      positive.includes('secret') || positive.includes('sensitive') || Buffer.byteLength(positive, 'utf8') > 8192) {
    throw new Error('failure-only diagnostic positive fixture exposed unsafe or missing content');
  }
  const unavailable = `${FAILURE_DIAGNOSTIC_HEADER}diagnostic unavailable\n`;
  const malformedReason = `reason=${GO_FAILURE_REASONS.malformedOrUnexpected} status=1\n`;
  const excluded = [
    ['oversized event count', encode(Array.from({ length: FAILURE_DIAGNOSTIC_MAX_EVENTS + 1 }, () => ({ Package: pkg, Action: 'output', Output: 'bounded' })))],
    ['oversized event line', encode([{ Package: pkg, Action: 'output', Output: 'x'.repeat(FAILURE_DIAGNOSTIC_MAX_LINE_BYTES + 1) }])],
    ['oversized input', 'x'.repeat(FAILURE_DIAGNOSTIC_MAX_BYTES + 1)],
  ];
  for (const [label, stdout] of excluded) {
    const result = failureOnlyGoTestDiagnostic(stdout, 1, pkg, names, zeroContextSites);
    if (result !== unavailable || result.includes('TestOne') || result.includes('TestOther')) throw new Error(`failure-only diagnostic did not bound ${label}`);
  }
  const malformedCases = [
    ['malformed event', '{not-json'],
    ['unexpected package', encode([{ Package: 'fixture/other', Action: 'fail', Test: 'TestOne' }])],
    ['unknown test name', encode([{ Package: pkg, Action: 'fail', Test: 'TestOther', Output: 'must stay suppressed' }])],
  ];
  for (const [label, stdout] of malformedCases) {
    const result = failureOnlyGoTestDiagnostic(stdout, 1, pkg, names, zeroContextSites);
    if (!result.includes(malformedReason) || result.includes('TestOther') || result.includes('must stay suppressed')) {
      throw new Error(`failure-only diagnostic did not safely classify ${label}`);
    }
  }
  const excludedSites = [
    ['unknown source site', encode([
      { Package: pkg, Action: 'start' },
      { Package: pkg, Action: 'fail', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST },
      { Package: pkg, Action: 'output', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST, Output: 'manager_test.go:999999: hidden details' },
    ])],
  ];
  for (const [label, stdout] of excludedSites) {
    const result = failureOnlyGoTestDiagnostic(stdout, 1, pkg, names, zeroContextSites);
    if (result !== unavailable || result.includes('TestOne') || result.includes('TestOther')) throw new Error(`failure-only diagnostic did not exclude ${label}`);
  }
  const wrongPackage = encode([{ Package: 'fixture/other', Action: 'output', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST, Output: 'manager_test.go:1: hidden' }]);
  if (!failureOnlyGoTestDiagnostic(wrongPackage, 1, pkg, names, zeroContextSites).includes(malformedReason)) throw new Error('failure-only diagnostic did not classify a wrong package');
  const wrongTest = failureOnlyGoTestDiagnostic(encode([
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'fail', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST },
    { Package: pkg, Action: 'output', Test: 'TestOne', Output: `manager_test.go:${sourceSiteLines[0]}: hidden` },
  ]), 1, pkg, names, zeroContextSites);
  if (!wrongTest.includes(`fail ${ZERO_CONTEXT_DIAGNOSTIC_TEST}\n`) || wrongTest.includes('site ')) throw new Error('failure-only diagnostic mapped a source site from the wrong test');
  if (failureOnlyGoTestDiagnostic(encode(events), 0, pkg, names, zeroContextSites, 'panic: token must remain silent') !== '') throw new Error('successful Go run emitted failure diagnostics');

  const manyNames = new Set(Array.from({ length: FAILURE_DIAGNOSTIC_MAX_IDS + 8 }, (_, index) => `Test${index}`));
  const manyFailures = [{ Package: pkg, Action: 'start' }, ...[...manyNames].flatMap((Test) => [
    { Package: pkg, Action: 'run', Test },
    { Package: pkg, Action: 'fail', Test },
  ]), { Package: pkg, Action: 'fail' }];
  const bounded = failureOnlyGoTestDiagnostic(encode(manyFailures), 1, pkg, manyNames, zeroContextSites);
  if (!bounded.endsWith('additional diagnostic entries omitted: 8\n') ||
      bounded.split('\n').filter((line) => line.startsWith('fail Test')).length !== FAILURE_DIAGNOSTIC_MAX_IDS ||
      Buffer.byteLength(bounded, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('failure-only diagnostic count bound failed');
  }

  const collisionNames = new Set([
    'TestFailure',
    ZERO_CONTEXT_DIAGNOSTIC_TEST,
    ...Array.from({ length: FAILURE_DIAGNOSTIC_MAX_IDS + 8 }, (_, index) => `TestUnfinished${index}`),
  ]);
  const collisionEvents = [
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'run', Test: 'TestFailure' },
    { Package: pkg, Action: 'fail', Test: 'TestFailure' },
    { Package: pkg, Action: 'run', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST },
    { Package: pkg, Action: 'output', Test: ZERO_CONTEXT_DIAGNOSTIC_TEST, Output: `manager_test.go:${sourceSiteLines[0]}: private fixture detail` },
    ...[...collisionNames].filter((name) => name.startsWith('TestUnfinished')).map((Test) => ({ Package: pkg, Action: 'run', Test })),
    { Package: pkg, Action: 'fail' },
  ];
  const collision = failureOnlyGoTestDiagnostic(encode(collisionEvents), 1, pkg, collisionNames, zeroContextSites);
  const collisionIds = collision.split('\n').filter((line) => /^(?:fail |skip |site |last_active |source |unfinished )/.test(line));
  if (!collision.includes('fail TestFailure\n') ||
      !collision.includes(`site ${ZERO_CONTEXT_DIAGNOSTIC_TEST} ${zeroContextSites.get(sourceSiteLines[0])}\n`) ||
      !collision.includes(`unfinished_expected=${FAILURE_DIAGNOSTIC_MAX_IDS + 9} `) ||
      collisionIds.length > FAILURE_DIAGNOSTIC_MAX_IDS ||
      !collision.endsWith('additional diagnostic entries omitted: 12\n') ||
      Buffer.byteLength(collision, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('failure-only diagnostic did not prioritize named failure and mapped site over colliding unfinished IDs');
  }

  const packageOnlyFail = failureOnlyGoTestDiagnostic(encode([
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'output', Output: 'TOKEN=hostile /private/path body must never print' },
    { Package: pkg, Action: 'fail', Output: 'panic: hostile raw body /secret/path' },
  ]), 7, pkg, names, zeroContextSites);
  if (!packageOnlyFail.includes(`reason=${GO_FAILURE_REASONS.packageFail} status=7\n`) ||
      !packageOnlyFail.includes('crash=panic\n') || /TOKEN|hostile|private|secret|panic:|body|path/.test(packageOnlyFail) || Buffer.byteLength(packageOnlyFail, 'utf8') > FAILURE_DIAGNOSTIC_MAX_OUTPUT_BYTES) {
    throw new Error('package-level failure diagnostic leaked hostile output or status');
  }

  const crashFixture = (marker, stderr = '', pathLine = '') => failureOnlyGoTestDiagnostic(encode([
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'run', Test: 'TestOne' },
    { Package: pkg, Action: 'output', Output: `${marker}${pathLine ? `\n${pathLine}` : ''}\nraw symbol secret payload` },
    { Package: pkg, Action: 'fail' },
  ]), 1, pkg, names, zeroContextSites, stderr);
  const timeoutDiagnostic = crashFixture('panic: test timed out after 10m0s', '', '/tmp/private/internal/workloads/manager_test.go:123 +0xSECRET');
  if (!timeoutDiagnostic.includes('crash=timeout\n') || !timeoutDiagnostic.includes('last_active=TestOne') ||
      !timeoutDiagnostic.includes('last_active TestOne\n') || !timeoutDiagnostic.includes('source internal/workloads/manager_test.go:123\n') ||
      /\/tmp\/private|SECRET|raw symbol|secret payload|panic: test/.test(timeoutDiagnostic)) {
    throw new Error('failure-only timeout diagnostic progress/source allowlist control failed');
  }
  const stderrTimeoutDiagnostic = crashFixture('', 'panic: test timed out after 3m0s\n/tmp/private/internal/workloads/manager_test.go:124 +0xSECRET');
  if (!stderrTimeoutDiagnostic.includes('crash=timeout\n') || !stderrTimeoutDiagnostic.includes('source internal/workloads/manager_test.go:124\n') ||
      /\/tmp\/private|SECRET|panic: test/.test(stderrTimeoutDiagnostic)) throw new Error('failure-only private-stderr classifier/source privacy control failed');
  const deadlockDiagnostic = crashFixture('fatal error: all goroutines are asleep - deadlock!');
  if (!deadlockDiagnostic.includes('crash=deadlock\n')) throw new Error('failure-only deadlock classification control failed');
  const panicDiagnostic = crashFixture('panic: runtime error: index out of range');
  if (!panicDiagnostic.includes('crash=panic\n') || /index out of range/.test(panicDiagnostic)) throw new Error('failure-only panic classification/privacy control failed');
  const buildDiagnostic = crashFixture('# vram-governor/internal/workloads\ninternal/workloads/manager_test.go:234:9: undefined: privateSymbol\nFAIL vram-governor/internal/workloads [build failed]', '', '');
  if (!buildDiagnostic.includes('crash=build_error\n') || !buildDiagnostic.includes('source internal/workloads/manager_test.go:234\n') ||
      /privateSymbol|\[build failed\]/.test(buildDiagnostic)) throw new Error('failure-only compiler classification/source privacy control failed');
  const unknownDiagnostic = failureOnlyGoTestDiagnostic(encode([
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'output', Output: 'request=/unowned/private/path unknownSymbol secret words' },
    { Package: pkg, Action: 'fail' },
  ]), 1, pkg, names, zeroContextSites, 'hostile stderr /arbitrary/path token=hidden');
  if (!unknownDiagnostic.includes('crash=unknown\n') || /unowned|private|unknownSymbol|secret words|hostile|arbitrary|token=hidden/.test(unknownDiagnostic)) {
    throw new Error('failure-only unknown classification leaked hostile output or stderr');
  }
  const unownedSourceDiagnostic = crashFixture('panic: controlled', '', '/tmp/private/internal/api/foreign.go:73:2: arbitrary body');
  if (!unownedSourceDiagnostic.includes('crash=panic\n') || unownedSourceDiagnostic.includes('source ') || /foreign\.go|arbitrary body/.test(unownedSourceDiagnostic)) {
    throw new Error('failure-only source location accepted a non-owned Go file');
  }
  const stderrOversized = failureOnlyGoTestDiagnostic(encode([{ Package: pkg, Action: 'start' }, { Package: pkg, Action: 'fail' }]), 1, pkg, names, zeroContextSites, 'x'.repeat(FAILURE_DIAGNOSTIC_MAX_BYTES));
  if (stderrOversized !== unavailable) throw new Error('failure-only diagnostic did not bound private stderr');
  const stderrEventsOversized = failureOnlyGoTestDiagnostic(encode([{ Package: pkg, Action: 'start' }, { Package: pkg, Action: 'fail' }]), 1, pkg, names, zeroContextSites,
    Array.from({ length: FAILURE_DIAGNOSTIC_MAX_EVENTS + 1 }, () => 'bounded').join('\n'));
  if (stderrEventsOversized !== unavailable) throw new Error('failure-only diagnostic did not bound private stderr event count');
  const outputLineOversized = crashFixture('panic: marker', 'x'.repeat(FAILURE_DIAGNOSTIC_MAX_LINE_BYTES + 1));
  if (outputLineOversized !== unavailable) throw new Error('failure-only diagnostic did not bound private stderr line length');
  const inventory = [
    { Package: pkg, Action: 'start' },
    { Package: pkg, Action: 'run', Test: 'TestOne' },
    { Package: pkg, Action: 'pass', Test: 'TestOne' },
    { Package: pkg, Action: 'pass' },
  ];
  const missingInventory = failureOnlyGoTestDiagnostic(encode(inventory), 1, pkg, names, zeroContextSites);
  if (!missingInventory.includes(`reason=${GO_FAILURE_REASONS.missingExactInventory} status=1\n`)) throw new Error('incomplete exact inventory diagnostic control failed');
  const missingPackagePass = failureOnlyGoTestDiagnostic(encode(inventory.slice(0, -1)), 1, pkg, names, zeroContextSites);
  if (!missingPackagePass.includes(`reason=${GO_FAILURE_REASONS.missingPackagePass} status=1\n`)) throw new Error('missing package PASS diagnostic control failed');
  const completeInventory = [
    { Package: pkg, Action: 'start' },
    ...[...names].sort((left, right) => left.split('/').length - right.split('/').length)
      .map((Test) => ({ Package: pkg, Action: 'run', Test })),
    ...[...names].sort((left, right) => right.split('/').length - left.split('/').length)
      .map((Test) => ({ Package: pkg, Action: 'pass', Test })),
    { Package: pkg, Action: 'pass' },
  ];
  const nonzeroWithoutNamedFailure = failureOnlyGoTestDiagnostic(encode(completeInventory), 9, pkg, names, zeroContextSites);
  if (!nonzeroWithoutNamedFailure.includes(`reason=${GO_FAILURE_REASONS.nonzeroWithoutNamedFailure} status=9\n`)) {
    throw new Error('nonzero API status without named failure diagnostic control failed');
  }
  const invalidStatus = failureOnlyGoTestDiagnostic(encode(completeInventory), 256, pkg, names, zeroContextSites);
  if (invalidStatus !== unavailable) throw new Error('failure-only diagnostic printed an unbounded status value');
  const strictFailureEvents = [events[0], { Package: pkg, Action: 'fail', Test: 'TestOne' }];
  try { parseGoTestStream(encode(strictFailureEvents), 1, pkg, names); } catch (error) {
    if (!String(error.message).includes('Go fail')) throw new Error(`failure diagnostic changed strict parser behavior: ${error.message}`);
    console.log('SOURCEONLY: failure-only Go diagnostics closed reason enums, numeric status, source-bound sites, privacy, and bounds passed; strict parser remains rejecting');
    return;
  }
  throw new Error('failure diagnostic accidentally granted Go run acceptance');
}

function sourceMode() {
  testGoEventParserControls();
  const sources = loadSources();
  testFailureOnlyGoTestDiagnosticControls(sources['internal/workloads/manager_test.go'], sources['internal/api/node_commands_test.go']);
  const issues = inspect(sources);
  if (issues.length) {
    for (const issue of issues) console.error(`SOURCEONLY: ${issue}`);
    throw new Error('runtime profile projection source controls failed');
  }

  const fabricated = { ...sources };
  fabricated['internal/workloads/manager.go'] = fabricated['internal/workloads/manager.go'].replace(
    'm.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "runtime.profile_switched"',
    'refreshed.CapacitySource = "runtime-profile:" + desired.ID; refreshed.CapacityVerified = true; m.audit(ctx, workload.Request.OwnerID, workload.Request.ID, "runtime.profile_switched"',
  );
  if (!inspect(fabricated).some((issue) => issue.includes('fabricates verified capacity'))) {
    throw new Error('SOURCEONLY positive control did not detect desired-to-verified fabrication');
  }

  const missingWaiter = { ...sources };
  missingWaiter['internal/api/node_commands.go'] = missingWaiter['internal/api/node_commands.go'].replace('s.projectRuntimeProfileResult(current, result)', 'nil');
  if (!inspect(missingWaiter).some((issue) => issue.includes('command waiter does not synchronize'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing waiter projection');
  }

  const missingTest = { ...sources };
  missingTest['internal/api/node_commands_test.go'] = missingTest['internal/api/node_commands_test.go'].replace('TestRuntimeProfileProjectionBeforeWaiterAdmission', 'RemovedRuntimeProfileProjectionBeforeWaiterAdmission');
  if (!inspect(missingTest).some((issue) => issue.includes('TestRuntimeProfileProjectionBeforeWaiterAdmission'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing composed production-path test');
  }

  const operationBeforeSnapshot = { ...sources };
  operationBeforeSnapshot['internal/workloads/residency.go'] = operationBeforeSnapshot['internal/workloads/residency.go'].replace(
    'residency, err := m.store.GetModelResidency(ctx, targetID, model)',
    'm.beginResidencyOperation(ctx)\n\tresidency, err := m.store.GetModelResidency(ctx, targetID, model)',
  );
  if (operationBeforeSnapshot['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(operationBeforeSnapshot).some((issue) => issue.includes('read the durable snapshot before acquiring the operation fence'))) {
    throw new Error('SOURCEONLY mutant control did not detect operation acquisition before the durable snapshot');
  }

  const missingPreAcquireSnapshotGuards = { ...sources };
  missingPreAcquireSnapshotGuards['internal/workloads/residency.go'] = missingPreAcquireSnapshotGuards['internal/workloads/residency.go'].replace(
    'if err := ctx.Err(); err != nil {\n\t\treturn nil, nil, err\n\t}\n\treleaseOperation, operationErr := m.beginResidencyOperation(ctx)',
    'releaseOperation, operationErr := m.beginResidencyOperation(ctx)',
  );
  if (missingPreAcquireSnapshotGuards['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(missingPreAcquireSnapshotGuards).some((issue) => issue.includes('post-read/post-acquire cancellation checks'))) {
    throw new Error('SOURCEONLY mutant control did not detect cancellation after the snapshot and before operation acquisition');
  }

  const missingPostAcquireContextFence = { ...sources };
  missingPostAcquireContextFence['internal/workloads/residency.go'] = missingPostAcquireContextFence['internal/workloads/residency.go'].replace(
    'defer releaseOperation()\n\tif err := ctx.Err(); err != nil {\n\t\treturn nil, nil, err\n\t}\n\ttarget, targetGeneration, err = m.reconcileResidencyGenerationContext(ctx, target, residency, targetGeneration)',
    'defer releaseOperation()\n\ttarget, targetGeneration, err = m.reconcileResidencyGenerationContext(ctx, target, residency, targetGeneration)',
  );
  if (missingPostAcquireContextFence['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(missingPostAcquireContextFence).some((issue) => issue.includes('post-read/post-acquire cancellation checks'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing post-acquisition context fence');
  }

  const missingPostReconcileContextFence = { ...sources };
  missingPostReconcileContextFence['internal/workloads/residency.go'] = missingPostReconcileContextFence['internal/workloads/residency.go'].replace(
    'if err != nil {\n\t\treturn residency, nil, err\n\t}\n\tif err := ctx.Err(); err != nil {\n\t\treturn nil, nil, err\n\t}\n\tpreviousPolicy := residency.Policy',
    'if err != nil {\n\t\treturn residency, nil, err\n\t}\n\tpreviousPolicy := residency.Policy',
  );
  if (missingPostReconcileContextFence['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(missingPostReconcileContextFence).some((issue) => issue.includes('post-read/post-acquire cancellation checks'))) {
    throw new Error('SOURCEONLY mutant control did not detect cancellation after generation reconciliation');
  }

  const movedHighWaterCommitContextCheck = { ...sources };
  const managerSource = movedHighWaterCommitContextCheck['internal/workloads/manager.go'];
  const contextMethodAt = managerSource.indexOf('func (m *Manager) reconcileResidencyGenerationContext(');
  const contextCheckAt = managerSource.indexOf('\t\tif err := ctx.Err(); err != nil {', contextMethodAt);
  const contextCheckEnd = managerSource.indexOf('\n\t\tcurrent, found :=', contextCheckAt);
  const contextCheckBlock = contextCheckAt < 0 || contextCheckEnd < 0 ? '' : managerSource.slice(contextCheckAt, contextCheckEnd);
  let movedContextSource = contextCheckBlock
    ? managerSource.slice(0, contextCheckAt) + managerSource.slice(contextCheckEnd)
    : managerSource;
  const highWaterAssignmentAt = movedContextSource.indexOf('\t\t\t m.targetGenerations[target.ID] = generation', contextMethodAt);
  const exactAssignmentAt = highWaterAssignmentAt >= 0 ? highWaterAssignmentAt : movedContextSource.indexOf('\t\t\t' + 'm.targetGenerations[target.ID] = generation', contextMethodAt);
  const postAssignmentUnlock = exactAssignmentAt < 0 ? -1 : movedContextSource.indexOf('\n\t\tm.mu.Unlock()', exactAssignmentAt);
  if (contextCheckBlock && postAssignmentUnlock >= 0) {
    movedContextSource = movedContextSource.slice(0, postAssignmentUnlock) + '\n' + contextCheckBlock + movedContextSource.slice(postAssignmentUnlock);
  }
  movedHighWaterCommitContextCheck['internal/workloads/manager.go'] = movedContextSource;
  if (!contextCheckBlock || postAssignmentUnlock < 0 || !inspect(movedHighWaterCommitContextCheck).some((issue) => issue.includes('high-water commit must preserve legacy callers and check Configure cancellation'))) {
    throw new Error('SOURCEONLY mutant control did not reject moving cancellation behind high-water generation publication');
  }

  const configureUsesLegacyGenerationRecovery = { ...sources };
  configureUsesLegacyGenerationRecovery['internal/workloads/residency.go'] = configureUsesLegacyGenerationRecovery['internal/workloads/residency.go'].replace(
    'm.reconcileResidencyGenerationContext(ctx, target, residency, targetGeneration)',
    'm.reconcileResidencyGeneration(target, residency, targetGeneration)',
  );
  if (configureUsesLegacyGenerationRecovery['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(configureUsesLegacyGenerationRecovery).some((issue) => issue.includes('capture its target/generation and read the durable snapshot'))) {
    throw new Error('SOURCEONLY mutant control did not detect omitted ConfigureResidency context propagation');
  }

  const cancellationTestOmitsCancel = { ...sources };
  cancellationTestOmitsCancel['internal/workloads/manager_test.go'] = cancellationTestOmitsCancel['internal/workloads/manager_test.go'].replace(
    '\n\tcancelConfigure()\n\tclaim.Release()\n\tselect {',
    '\n\t/* cancellation omitted */\n\tclaim.Release()\n\tselect {',
  );
  if (cancellationTestOmitsCancel['internal/workloads/manager_test.go'] === sources['internal/workloads/manager_test.go'] ||
      !inspect(cancellationTestOmitsCancel).some((issue) => issue.includes('bounded cancel-while-result-claim-held case'))) {
    throw new Error('SOURCEONLY mutant control did not detect an omitted controlled cancellation');
  }

  const cancellationTestOmitsNoMutationAssertions = { ...sources };
  cancellationTestOmitsNoMutationAssertions['internal/workloads/manager_test.go'] = cancellationTestOmitsNoMutationAssertions['internal/workloads/manager_test.go']
    .replace('if got := cancelManager.targetGeneration(cancelTarget.ID); got != preCancelGeneration {', 'if false {')
    .replace('if postCancelProjectedGeneration != preCancelProjectedGeneration {', 'if false {')
    .replace('durableAfter == nil || !reflect.DeepEqual(seeded, durableAfter)', 'durableAfter == nil');
  if (cancellationTestOmitsNoMutationAssertions['internal/workloads/manager_test.go'] === sources['internal/workloads/manager_test.go'] ||
      !inspect(cancellationTestOmitsNoMutationAssertions).some((issue) => issue.includes('bounded cancel-while-result-claim-held case'))) {
    throw new Error('SOURCEONLY mutant control did not detect omitted live/projected/durable no-mutation assertions');
  }

  const missingSnapshotRowGuard = { ...sources };
  missingSnapshotRowGuard['internal/workloads/residency.go'] = missingSnapshotRowGuard['internal/workloads/residency.go'].replace(
    'if residency == nil {\n\t\treturn nil, nil, fmt.Errorf("model residency snapshot is unavailable")\n\t}',
    'if false {\n\t\treturn nil, nil, fmt.Errorf("model residency snapshot is unavailable")\n\t}',
  );
  if (missingSnapshotRowGuard['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(missingSnapshotRowGuard).some((issue) => issue.includes('missing pre-operation snapshot'))) {
    throw new Error('SOURCEONLY mutant control did not detect an absent durable snapshot guard');
  }

  const missingPostReadTargetFence = { ...sources };
  missingPostReadTargetFence['internal/workloads/residency.go'] = missingPostReadTargetFence['internal/workloads/residency.go'].replace(
    'residencyRevision := residency.Revision\n\tif !m.targetFenceMatches(target, targetGeneration) {',
    'residencyRevision := residency.Revision\n\tif false {',
  );
  if (missingPostReadTargetFence['internal/workloads/residency.go'] === sources['internal/workloads/residency.go'] ||
      !inspect(missingPostReadTargetFence).some((issue) => issue.includes('post-reconcile target/CAS fence'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing post-reconcile target fence');
  }

  const unrelatedSnapshotReaderCanConsumeBarrier = { ...sources };
  unrelatedSnapshotReaderCanConsumeBarrier['internal/api/node_commands_test.go'] = unrelatedSnapshotReaderCanConsumeBarrier['internal/api/node_commands_test.go'].replace(
    'block := s.armed && owner && err == nil && row != nil && targetID == "node-a-runtime" && model == "model"',
    'block := s.armed && targetID == "node-a-runtime" && model == "model"',
  );
  if (unrelatedSnapshotReaderCanConsumeBarrier['internal/api/node_commands_test.go'] === sources['internal/api/node_commands_test.go'] ||
      !inspect(unrelatedSnapshotReaderCanConsumeBarrier).some((issue) => issue.includes('snapshot barrier can be consumed by an unrelated reader'))) {
    throw new Error('SOURCEONLY mutant control did not detect an unrelated reader consuming the owner barrier');
  }

  const configureOwnerMarkerOmitted = { ...sources };
  configureOwnerMarkerOmitted['internal/api/node_commands_test.go'] = configureOwnerMarkerOmitted['internal/api/node_commands_test.go'].replace(
    'context.WithValue(context.Background(), profileResidencySnapshotBarrierContextKey{}, true)',
    'context.Background()',
  );
  if (configureOwnerMarkerOmitted['internal/api/node_commands_test.go'] === sources['internal/api/node_commands_test.go'] ||
      !inspect(configureOwnerMarkerOmitted).some((issue) => issue.includes('snapshot barrier can be consumed by an unrelated reader'))) {
    throw new Error('SOURCEONLY mutant control did not detect an unowned ConfigureResidency read');
  }

  const snapshotEntryWithoutSuccessfulRow = { ...sources };
  snapshotEntryWithoutSuccessfulRow['internal/api/node_commands_test.go'] = snapshotEntryWithoutSuccessfulRow['internal/api/node_commands_test.go'].replace(
    'block := s.armed && owner && err == nil && row != nil && targetID == "node-a-runtime" && model == "model"',
    'block := s.armed && owner && targetID == "node-a-runtime" && model == "model"',
  );
  if (snapshotEntryWithoutSuccessfulRow['internal/api/node_commands_test.go'] === sources['internal/api/node_commands_test.go'] ||
      !inspect(snapshotEntryWithoutSuccessfulRow).some((issue) => issue.includes('snapshot barrier can be consumed by an unrelated reader'))) {
    throw new Error('SOURCEONLY mutant control did not detect entry before a successful owner snapshot');
  }

  const synchronousBarrierSubmit = { ...sources };
  synchronousBarrierSubmit['internal/api/node_commands_test.go'] = synchronousBarrierSubmit['internal/api/node_commands_test.go'].replace(
    'go func() {\n\t\t\t\t\tdefer close(barrierSubmitJoined)\n\t\t\t\t\tworkload, admitted, submitErr := manager.Submit(barrierSubmitCtx, request)\n\t\t\t\t\tbarrierSubmitResult <- submitCompletion{workload: workload, admitted: admitted, err: submitErr}\n\t\t\t\t}()',
    'workload, admitted, submitErr := manager.Submit(barrierSubmitCtx, request)\n\t\t\t\tbarrierSubmitResult <- submitCompletion{workload: workload, admitted: admitted, err: submitErr}',
  );
  if (!inspect(synchronousBarrierSubmit).some((issue) => issue.includes('barrier worker cleanup does not release both barriers'))) {
    throw new Error('SOURCEONLY mutant control did not detect synchronous barrier Submit before delayed-command receive');
  }

  const barrierCleanupMutants = [
    ['resultJoined := join(resultDone, resultHandlerStarted)', 'resultJoined := true', 'result-handler join'],
    ['registrationJoined := join(registrationDone, registrationStarted)', 'registrationJoined := true', 'registration-worker join'],
    ['configureWorkerJoined := join(configureJoined, configureStarted)', 'configureWorkerJoined := true', 'ConfigureResidency worker join'],
    ['submitJoined := join(barrierSubmitJoined, barrierSubmitStarted)', 'submitJoined := true', 'Submit worker join'],
    ['residencySnapshotStore.releaseSnapshot()', '/* snapshot barrier release omitted */', 'second residency barrier release'],
    ['releaseResult()', '/* result barrier release omitted */', 'result-CAS barrier release'],
    ['cancelBarrierSubmit()', '/* Submit cancellation omitted */', 'Submit context cancellation'],
    ['cancelConfigure()', '/* configuration cancellation omitted */', 'ConfigureResidency cancellation'],
    ['case <-timer.C:\n\t\t\t\t\t\treturn false', 'case <-timer.C:\n\t\t\t\t\t\treturn true', 'join timeout guard'],
    ['if barrierCase && !barrierCleanupSafe {\n\t\t\t\t\tt.Errorf("barrier worker join was uncertain; preserving isolated manager/server fixture instead of closing it")', 'if false {\n\t\t\t\t\tt.Errorf("barrier worker join was uncertain; preserving isolated manager/server fixture instead of closing it")', 'cleanup guard bypass'],
  ];
  for (const [before, after, label] of barrierCleanupMutants) {
    const mutant = { ...sources };
    mutant['internal/api/node_commands_test.go'] = mutant['internal/api/node_commands_test.go'].replace(before, after);
    if (mutant['internal/api/node_commands_test.go'] === sources['internal/api/node_commands_test.go'] ||
        !inspect(mutant).some((issue) => issue.includes('barrier worker cleanup does not release both barriers'))) {
      throw new Error(`SOURCEONLY mutant control did not detect missing ${label}`);
    }
  }

  const residencyOnlyFixtureSelection = { ...sources };
  residencyOnlyFixtureSelection['internal/api/node_commands_test.go'] = residencyOnlyFixtureSelection['internal/api/node_commands_test.go'].replace(
    'if testCase.residencyWriterCASBarrier || testCase.resultCASLifecycleBarrier {',
    'if testCase.residencyWriterCASBarrier {',
  );
  if (!inspect(residencyOnlyFixtureSelection).some((issue) => issue.includes('both result-CAS barrier cases must use the existing manual pass-through fixture'))) {
    throw new Error('SOURCEONLY mutant control did not detect registration-barrier fallback to testServer');
  }

  const barrierFixtureFallback = { ...sources };
  barrierFixtureFallback['internal/api/node_commands_test.go'] = barrierFixtureFallback['internal/api/node_commands_test.go'].replace(
    'server, manager, residencySnapshotStore, cleanup = profileResidencyBarrierServer(t)',
    'server, manager, residencySnapshotStore, cleanup = testServer(t)',
  );
  if (!inspect(barrierFixtureFallback).some((issue) => issue.includes('both result-CAS barrier cases must use the existing manual pass-through fixture'))) {
    throw new Error('SOURCEONLY mutant control did not detect barrier fixture fallback to testServer');
  }

  const automaticTempDirFixtureCleanup = { ...sources };
  automaticTempDirFixtureCleanup['internal/api/node_commands_test.go'] = automaticTempDirFixtureCleanup['internal/api/node_commands_test.go'].replace(
    'backing := store.NewMemoryStore()',
    'tempDir := t.TempDir()\n\t_ = tempDir\n\tbacking := store.NewMemoryStore()',
  );
  if (!inspect(automaticTempDirFixtureCleanup).some((issue) => issue.includes('both result-CAS barrier cases must use the existing manual pass-through fixture'))) {
    throw new Error('SOURCEONLY mutant control did not detect t.TempDir in the manually owned barrier fixture');
  }

  const automaticCleanupFixture = { ...sources };
  automaticCleanupFixture['internal/api/node_commands_test.go'] = automaticCleanupFixture['internal/api/node_commands_test.go'].replace(
    't.Helper()\n\tbacking := store.NewMemoryStore()',
    't.Helper()\n\tt.Cleanup(func() {})\n\tbacking := store.NewMemoryStore()',
  );
  if (!inspect(automaticCleanupFixture).some((issue) => issue.includes('both result-CAS barrier cases must use the existing manual pass-through fixture'))) {
    throw new Error('SOURCEONLY mutant control did not detect t.Cleanup in the manually owned barrier fixture');
  }

  const unboundedCASConflictSubmit = { ...sources };
  unboundedCASConflictSubmit['internal/api/node_commands_test.go'] = unboundedCASConflictSubmit['internal/api/node_commands_test.go'].replace(
    'submitCtx, submitCancel = context.WithTimeout(context.Background(), 2*time.Second)',
    'submitCtx, submitCancel = context.WithCancel(context.Background())',
  );
  if (!inspect(unboundedCASConflictSubmit).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect an unbounded CAS-conflict submission');
  }

  const swallowedCASConflictError = { ...sources };
  swallowedCASConflictError['internal/api/node_commands_test.go'] = swallowedCASConflictError['internal/api/node_commands_test.go'].replace(
    '!errors.Is(submitErr, context.DeadlineExceeded) || submitContextErr != context.DeadlineExceeded',
    'false',
  );
  if (!inspect(swallowedCASConflictError).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect swallowing of unexpected Submit errors');
  }

  const missingCASConflictCancel = { ...sources };
  missingCASConflictCancel['internal/api/node_commands_test.go'] = missingCASConflictCancel['internal/api/node_commands_test.go'].replace('\t\t\tsubmitCancel()\n', '');
  if (!inspect(missingCASConflictCancel).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect omitted bounded-submit cancellation');
  }

  const unjoinedCASConflictSubmit = { ...sources };
  unjoinedCASConflictSubmit['internal/api/node_commands_test.go'] = unjoinedCASConflictSubmit['internal/api/node_commands_test.go'].replace(
    '_, _, submitErr := manager.Submit(submitCtx, request)',
    'go manager.Submit(submitCtx, request)',
  );
  if (!inspect(unjoinedCASConflictSubmit).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect an unsettled/asynchronous CAS-conflict submission');
  }

  const missingCASConflictStatus = { ...sources };
  missingCASConflictStatus['internal/api/node_commands_test.go'] = missingCASConflictStatus['internal/api/node_commands_test.go'].replace(
    'status != string(domain.NodeCommandSent)', 'false',
  );
  if (!inspect(missingCASConflictStatus).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect removal of exact SENT-state assertion');
  }

  const missingCASConflictPendingCapacity = { ...sources };
  missingCASConflictPendingCapacity['internal/api/node_commands_test.go'] = missingCASConflictPendingCapacity['internal/api/node_commands_test.go'].replace(
    'projected.CapacityVerified || projected.ContextLimit != 0 || projected.Slots != 0 || projected.CapacitySource != "runtime-profile:pending"',
    'false',
  );
  if (!inspect(missingCASConflictPendingCapacity).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect removal of pending zero-capacity assertions');
  }

  const missingCASConflictPendingPresence = { ...sources };
  missingCASConflictPendingPresence['internal/api/node_commands_test.go'] = missingCASConflictPendingPresence['internal/api/node_commands_test.go'].replace(
    'if !foundPending {\n\t\t\t\t\tt.Fatal("CAS-losing result retired the pending runtime target unexpectedly")\n\t\t\t\t}',
    'if false {\n\t\t\t\t\tt.Fatal("CAS-losing result retired the pending runtime target unexpectedly")\n\t\t\t\t}',
  );
  if (!inspect(missingCASConflictPendingPresence).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect a vacuous missing-pending-target path');
  }

  const missingCASConflictAdmissionGuard = { ...sources };
  missingCASConflictAdmissionGuard['internal/api/node_commands_test.go'] = missingCASConflictAdmissionGuard['internal/api/node_commands_test.go'].replace(
    'if row != nil && (row.Status == domain.WorkloadRunning || row.Status == domain.WorkloadSucceeded) {\n\t\t\t\t\tt.Fatalf("workload was admitted after durable result CAS conflict:',
    'if false {\n\t\t\t\t\tt.Fatalf("workload was admitted after durable result CAS conflict:',
  );
  if (!inspect(missingCASConflictAdmissionGuard).some((issue) => issue.includes('CAS-conflict submission is not bounded/settled'))) {
    throw new Error('SOURCEONLY mutant control did not detect removal of no-admission assertions');
  }

  const beforeDurableCAS = { ...sources };
  beforeDurableCAS['internal/api/node_commands.go'] = beforeDurableCAS['internal/api/node_commands.go'].replace(
    '_, updateErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision',
    'profileResultClaim.Project(result.Result); _, updateErr := s.workloadStore.CompareAndSwapNodeCommandRevision(ctx, command, expectedRevision',
  );
  if (!inspect(beforeDurableCAS).some((issue) => issue.includes('projects capacity before the durable result CAS'))) {
    throw new Error('SOURCEONLY mutant control did not detect pre-CAS capacity publication');
  }

  const missingDurableGuard = { ...sources };
  missingDurableGuard['internal/api/node_commands.go'] = missingDurableGuard['internal/api/node_commands.go'].replace('s.workloads.RuntimeProfileHistoryBlocker(nodeID, targetID, history)', '""');
  if (!inspect(missingDurableGuard).some((issue) => issue.includes('does not block a second unresolved physical profile switch'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing durable unresolved-switch guard');
  }

  const missingSendTicket = { ...sources };
  missingSendTicket['internal/api/node_commands.go'] = missingSendTicket['internal/api/node_commands.go'].replace(
    'releaseTicket, err = s.requireRuntimeProfileDispatchTicket(command.NodeID, command.Args, command.IdempotencyKey)',
    'releaseTicket, err = nil, nil',
  );
  if (!inspect(missingSendTicket).some((issue) => issue.includes('websocket send path lacks the exact current manager transition ticket'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing websocket dispatch ticket fence');
  }

  const missingDispatchClaim = { ...sources };
  missingDispatchClaim['internal/workloads/manager.go'] = missingDispatchClaim['internal/workloads/manager.go'].replace(
    'func (m *Manager) ClaimRuntimeProfileDispatch(nodeID, targetID string, args map[string]any, idempotencyKey string) (func(), error) {',
    'func (m *Manager) MissingRuntimeProfileDispatch(nodeID, targetID string, args map[string]any, idempotencyKey string) (func(), error) {',
  );
  if (!inspect(missingDispatchClaim).some((issue) => issue.includes('lifecycle dispatch claim is incomplete'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing lifecycle dispatch claim');
  }

  const missingHistoryBasis = { ...sources };
  missingHistoryBasis['internal/workloads/manager.go'] = missingHistoryBasis['internal/workloads/manager.go'].replace('target = transition.historyBasis', 'target = target');
  if (!inspect(missingHistoryBasis).some((issue) => issue.includes('pretransition history basis'))) {
    throw new Error('SOURCEONLY mutant control did not detect a lost prior accepted profile basis');
  }

  const missingZeroContextFence = { ...sources };
  missingZeroContextFence['internal/workloads/manager.go'] = missingZeroContextFence['internal/workloads/manager.go'].replace('profilePending || profileBlocker != ""', 'false');
  if (!inspect(missingZeroContextFence).some((issue) => issue.includes('zero-context pending admission'))) {
    throw new Error('SOURCEONLY mutant control did not detect pending zero-context admission bypass');
  }

  const missingResidentFence = { ...sources };
  missingResidentFence['internal/workloads/residency.go'] = missingResidentFence['internal/workloads/residency.go'].replace('releaseProfileTicket := m.lockRuntimeProfileTransitionForTarget(targetID)', 'releaseProfileTicket := func() {}');
  if (!inspect(missingResidentFence).some((issue) => issue.includes('resident metadata mutation is not fenced'))) {
    throw new Error('SOURCEONLY mutant control did not detect an unfenced resident generation mutation');
  }

  const missingHighWaterFence = { ...sources };
  missingHighWaterFence['internal/workloads/manager.go'] = missingHighWaterFence['internal/workloads/manager.go'].replace('if prior != nil && !prior.projected {', 'if false {');
  if (!inspect(missingHighWaterFence).some((issue) => issue.includes('lacks a revalidated current-ticket fence'))) {
    throw new Error('SOURCEONLY mutant control did not detect pending high-water generation mutation');
  }

  const blindAcceptedGenerationRefresh = { ...sources };
  blindAcceptedGenerationRefresh['internal/workloads/manager.go'] = blindAcceptedGenerationRefresh['internal/workloads/manager.go'].replace('m.refreshRuntimeProfileProjectedGenerationLocked(current)', '');
  if (!inspect(blindAcceptedGenerationRefresh).some((issue) => issue.includes('lacks a revalidated current-ticket fence'))) {
    throw new Error('SOURCEONLY mutant control did not detect loss of exact-profile generation reconciliation');
  }

  const generationBeforePendingCheck = { ...sources };
  generationBeforePendingCheck['internal/workloads/manager.go'] = generationBeforePendingCheck['internal/workloads/manager.go'].replace(
    'if prior != nil && !prior.projected {',
    'm.targetGenerations[target.ID] = generation; if prior != nil && !prior.projected {',
  );
  if (!inspect(generationBeforePendingCheck).some((issue) => issue.includes('can mutate generation before rejecting a pending ticket'))) {
    throw new Error('SOURCEONLY mutant control did not detect generation mutation moved before pending-ticket rejection');
  }

  const missingMaxGenerationGuard = { ...sources };
  missingMaxGenerationGuard['internal/workloads/manager.go'] = missingMaxGenerationGuard['internal/workloads/manager.go'].replace('if projection.TargetGeneration == ^uint64(0) {', 'if false {');
  if (!inspect(missingMaxGenerationGuard).some((issue) => issue.includes('can overflow uint64'))) {
    throw new Error('SOURCEONLY mutant control did not detect unchecked MaxUint64 high-water advancement');
  }

  const missingReplacementOverflowGuard = { ...sources };
  missingReplacementOverflowGuard['internal/workloads/manager.go'] = missingReplacementOverflowGuard['internal/workloads/manager.go'].replace(
    'if m.targetGenerations[target.ID] == ^uint64(0) {',
    'if false {',
  );
  if (!inspect(missingReplacementOverflowGuard).some((issue) => issue.includes('shared target replacement can wrap'))) {
    throw new Error('SOURCEONLY mutant control did not detect shared target generation wrap');
  }

  const missingRegistrationOverflowGuard = { ...sources };
  missingRegistrationOverflowGuard['internal/workloads/manager.go'] = missingRegistrationOverflowGuard['internal/workloads/manager.go'].replace(
    'publishGeneration == ^uint64(0)',
    'publishGeneration == 0',
  );
  if (!inspect(missingRegistrationOverflowGuard).some((issue) => issue.includes('target registration does not fail closed'))) {
    throw new Error('SOURCEONLY mutant control did not detect changed-fingerprint registration at MaxUint64');
  }

  const staleExhaustedRegistration = { ...sources };
  staleExhaustedRegistration['internal/workloads/manager.go'] = staleExhaustedRegistration['internal/workloads/manager.go'].replace('m.invalidateTargetAtExhaustedGenerationLocked(target.ID, previous)', '/* omitted invalidation */');
  if (!inspect(staleExhaustedRegistration).some((issue) => issue.includes('stale live route schedulable'))) {
    throw new Error('SOURCEONLY mutant control did not detect stale route retention after exhausted registration');
  }

  const staleExhaustedTelemetry = { ...sources };
  staleExhaustedTelemetry['internal/workloads/manager.go'] = staleExhaustedTelemetry['internal/workloads/manager.go'].replace('m.invalidateTargetAtExhaustedGenerationLocked(id, previous)', '/* omitted invalidation */');
  if (!inspect(staleExhaustedTelemetry).some((issue) => issue.includes('stale exhausted-generation capacity schedulable'))) {
    throw new Error('SOURCEONLY mutant control did not detect stale capacity after exhausted VRAM telemetry');
  }

  const aliasedResidentRemoval = { ...sources };
  aliasedResidentRemoval['internal/workloads/residency.go'] = aliasedResidentRemoval['internal/workloads/residency.go'].replace('residentModels := append([]string(nil), target.ResidentModels...)', 'residentModels := target.ResidentModels');
  if (!inspect(aliasedResidentRemoval).some((issue) => issue.includes('failed resident removal can mutate the live backing slice'))) {
    throw new Error('SOURCEONLY mutant control did not detect resident backing-slice aliasing');
  }

  const staleResidentRemoval = { ...sources };
  staleResidentRemoval['internal/workloads/residency.go'] = staleResidentRemoval['internal/workloads/residency.go'].replace('m.invalidateTargetAtExhaustedGenerationLocked(targetID, m.targets[targetID])', '/* omitted invalidation */');
  if (!inspect(staleResidentRemoval).some((issue) => issue.includes('failed resident removal can mutate the live backing slice'))) {
    throw new Error('SOURCEONLY mutant control did not detect stale route retention after exhausted resident update');
  }

  const aliasedDurableHotRepair = { ...sources };
  aliasedDurableHotRepair['internal/workloads/manager.go'] = aliasedDurableHotRepair['internal/workloads/manager.go'].replace('append(append([]string(nil), current.ResidentModels...), req.Model)', 'append(current.ResidentModels, req.Model)');
  if (!inspect(aliasedDurableHotRepair).some((issue) => issue.includes('durable HOT reconciliation can alias'))) {
    throw new Error('SOURCEONLY mutant control did not detect durable HOT reconciliation backing-slice aliasing');
  }

  const blockerMutationBeforePublish = { ...sources };
  blockerMutationBeforePublish['internal/workloads/manager.go'] = blockerMutationBeforePublish['internal/workloads/manager.go'].replace('prospectiveTargetBlocker = ""', 'm.runtimeProfileBlockedTargets[target.ID] = ""; prospectiveTargetBlocker = ""');
  if (!inspect(blockerMutationBeforePublish).some((issue) => issue.includes('mutates blocker state before fallible generation publication'))) {
    throw new Error('SOURCEONLY mutant control did not detect pre-publication blocker mutation');
  }

  const missingRetiredResurrectionGuard = { ...sources };
  missingRetiredResurrectionGuard['internal/workloads/manager.go'] = missingRetiredResurrectionGuard['internal/workloads/manager.go'].replace(
    'm.targetGenerations[target.ID] == ^uint64(0)',
    'm.targetGenerations[target.ID] == 0',
  );
  if (!inspect(missingRetiredResurrectionGuard).some((issue) => issue.includes('target registration does not fail closed'))) {
    throw new Error('SOURCEONLY mutant control did not detect exhausted-generation resurrection');
  }

  const missingRetirementOverflowGuard = { ...sources };
  missingRetirementOverflowGuard['internal/workloads/manager.go'] = missingRetirementOverflowGuard['internal/workloads/manager.go'].replace(
    'if m.targetGenerations[snapshot.id] == ^uint64(0) {',
    'if false {',
  );
  if (!inspect(missingRetirementOverflowGuard).some((issue) => issue.includes('node route retirement can wrap'))) {
    throw new Error('SOURCEONLY mutant control did not detect exhausted target retirement wrap');
  }

  const missingTransitionCapacityGuard = { ...sources };
  missingTransitionCapacityGuard['internal/workloads/residency.go'] = missingTransitionCapacityGuard['internal/workloads/residency.go'].replace(
    'targetGeneration == ^uint64(0)',
    'targetGeneration == 0',
  );
  if (!inspect(missingTransitionCapacityGuard).some((issue) => issue.includes('residency lifecycle can dispatch'))) {
    throw new Error('SOURCEONLY mutant control did not detect residency dispatch at an exhausted target generation');
  }

  const missingProfileSwitchGenerationGuard = { ...sources };
  missingProfileSwitchGenerationGuard['internal/workloads/manager.go'] = missingProfileSwitchGenerationGuard['internal/workloads/manager.go'].replace(
    'if generation >= ^uint64(0)-1 {',
    'if false {',
  );
  if (!inspect(missingProfileSwitchGenerationGuard).some((issue) => issue.includes('runtime profile transition can begin without room'))) {
    throw new Error('SOURCEONLY mutant control did not detect a profile transition without two generation fences');
  }

  const timingOnlyResidencyBarrier = { ...sources };
  timingOnlyResidencyBarrier['internal/api/node_commands_test.go'] = timingOnlyResidencyBarrier['internal/api/node_commands_test.go'].replace(
    'case <-residencySnapshotStore.entered:',
    'case <-time.After(30 * time.Millisecond):',
  );
  if (!inspect(timingOnlyResidencyBarrier).some((issue) => issue.includes('timing-only negative wait'))) {
    throw new Error('SOURCEONLY mutant control did not detect a timing-only API high-water race');
  }

  const missingSignedBoundaryCall = { ...sources };
  missingSignedBoundaryCall['internal/api/node_commands_linux_test.go'] = missingSignedBoundaryCall['internal/api/node_commands_linux_test.go'].replace(
    'runControllerResidencySignedNodeBoundary(t)',
    't.Skip("boundary omitted")',
  );
  if (!inspect(missingSignedBoundaryCall).some((issue) => issue.includes('Linux signed boundary wrapper is missing its real helper call'))) {
    throw new Error('SOURCEONLY mutant control did not detect a skipped Linux signed boundary wrapper');
  }

  const stubSignedBoundary = { ...sources };
  stubSignedBoundary['internal/api/node_commands_test.go'] = stubSignedBoundary['internal/api/node_commands_test.go'].replace(
    'runSignedNodeLifecycleBoundary(t)\n\trunSignedControllerWebsocketBoundary(t)\n\trunSignedNodeRecoveryBoundary(t)\n\trunSignedOfflineBoundary(t)',
    'return',
  );
  if (!inspect(stubSignedBoundary).some((issue) => issue.includes('signed controller/node helper is a stub'))) {
    throw new Error('SOURCEONLY mutant control did not detect a nonfunctional signed boundary helper');
  }

  const missingWarmAssertion = { ...sources };
  missingWarmAssertion['internal/api/node_commands_test.go'] = missingWarmAssertion['internal/api/node_commands_test.go'].replace(
    'warmed.Result["warm_model_bytes_verified"] != true',
    'false',
  );
  if (!inspect(missingWarmAssertion).some((issue) => issue.includes('event warm_verified lacks its substantive Go assertion'))) {
    throw new Error('SOURCEONLY mutant control did not detect a removed real warm-residency assertion');
  }

  const missingSignedPressurePath = { ...sources };
  missingSignedPressurePath['internal/api/node_commands_test.go'] = missingSignedPressurePath['internal/api/node_commands_test.go'].replace(
    'CgroupCurrentPath: "/sys/fs/cgroup/memory.current", PressurePath: "/proc/pressure/memory", PressureRefusalPercent: 100,',
    'CgroupCurrentPath: "/sys/fs/cgroup/memory.current", PressureRefusalPercent: 100,',
  );
  if (!inspect(missingSignedPressurePath).some((issue) => issue.includes('signed warm fixture lacks the real Linux PSI pressure source'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing signed-fixture PSI source');
  }

  const wrongSignedPressurePath = { ...sources };
  wrongSignedPressurePath['internal/api/node_commands_test.go'] = wrongSignedPressurePath['internal/api/node_commands_test.go'].replace(
    'PressurePath: "/proc/pressure/memory"',
    'PressurePath: "/tmp/pressure/memory"',
  );
  if (!inspect(wrongSignedPressurePath).some((issue) => issue.includes('signed warm fixture lacks the real Linux PSI pressure source'))) {
    throw new Error('SOURCEONLY mutant control did not detect a non-kernel pressure path');
  }

  const disabledSignedPressureGuard = { ...sources };
  disabledSignedPressureGuard['internal/api/node_commands_test.go'] = disabledSignedPressureGuard['internal/api/node_commands_test.go'].replace(
    'PressureRefusalPercent: 100',
    'PressureRefusalPercent: 0',
  );
  if (!inspect(disabledSignedPressureGuard).some((issue) => issue.includes('signed warm fixture lacks the real Linux PSI pressure source or its enabled refusal guard'))) {
    throw new Error('SOURCEONLY mutant control did not detect a disabled signed-fixture pressure refusal guard');
  }

  const missingRestartWireComparatorUse = { ...sources };
  missingRestartWireComparatorUse['internal/api/node_commands_test.go'] = missingRestartWireComparatorUse['internal/api/node_commands_test.go'].replace(
    '!signedBoundaryCommandResultJSONEqual(cleaned, restartReplay)',
    '!reflect.DeepEqual(cleaned.Result, restartReplay.Result)',
  );
  if (!inspect(missingRestartWireComparatorUse).some((issue) => issue.includes('signed restart replay lacks complete checked JSON wire equality'))) {
    throw new Error('SOURCEONLY mutant control did not detect bypassing the complete restart wire comparator');
  }

  const partialRestartWireComparator = { ...sources };
  partialRestartWireComparator['internal/api/node_commands_test.go'] = partialRestartWireComparator['internal/api/node_commands_test.go'].replace(
    'return bytes.Equal(beforeJSON, afterJSON)',
    'return reflect.DeepEqual(before.Result, after.Result)',
  );
  if (!inspect(partialRestartWireComparator).some((issue) => issue.includes('signed restart replay lacks complete checked JSON wire equality'))) {
    throw new Error('SOURCEONLY mutant control did not detect partial map-only restart equality');
  }

  const ignoredRestartMarshalError = { ...sources };
  ignoredRestartMarshalError['internal/api/node_commands_test.go'] = ignoredRestartMarshalError['internal/api/node_commands_test.go'].replace(
    'beforeJSON, err := json.Marshal(before)\n\tif err != nil {\n\t\treturn false\n\t}',
    'beforeJSON, _ := json.Marshal(before)',
  );
  if (!inspect(ignoredRestartMarshalError).some((issue) => issue.includes('signed restart replay lacks complete checked JSON wire equality'))) {
    throw new Error('SOURCEONLY mutant control did not detect ignoring a complete-payload marshal error');
  }

  const missingRestartMutationCounters = { ...sources };
  missingRestartMutationCounters['internal/api/node_commands_test.go'] = missingRestartMutationCounters['internal/api/node_commands_test.go'].replace(
    'node.runtime.loadCalls.Load() != beforeRestartLoads || node.runtime.unloadCalls.Load() != beforeRestartUnloads',
    'false',
  );
  if (!inspect(missingRestartMutationCounters).some((issue) => issue.includes('signed restart replay lacks complete checked JSON wire equality'))) {
    throw new Error('SOURCEONLY mutant control did not detect missing independent restart side-effect counters');
  }

  const missingRestartComparatorNegative = { ...sources };
  missingRestartComparatorNegative['internal/api/node_commands_test.go'] = missingRestartComparatorNegative['internal/api/node_commands_test.go'].replace(
    'reject("fence value", func(p *wsproto.CommandResultPayload) { p.Result["fencing_token"] = p.Result["fencing_token"].(float64) + 1 })\n',
    '',
  );
  if (!inspect(missingRestartComparatorNegative).some((issue) => issue.includes('signed restart JSON comparator controls lack a known-positive round-trip'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing fence-value negative');
  }

  const warmMarkerBeforeAssertion = { ...sources };
  warmMarkerBeforeAssertion['internal/api/node_commands_test.go'] = warmMarkerBeforeAssertion['internal/api/node_commands_test.go'].replace(
    'if !warmed.OK || warmed.Result["tier"] != "warm_ram" || warmed.Result["warm_model_bytes_verified"] != true',
    'boundaryEvent(t, "warm_verified")\n\tif !warmed.OK || warmed.Result["tier"] != "warm_ram" || warmed.Result["warm_model_bytes_verified"] != true',
  );
  if (!inspect(warmMarkerBeforeAssertion).some((issue) => issue.includes('event warm_verified is logged before its substantive Go assertion'))) {
    throw new Error('SOURCEONLY mutant control did not detect a warm proof marker moved before its assertion');
  }

  const missingPendingResourceAssertion = { ...sources };
  missingPendingResourceAssertion['internal/api/node_commands_test.go'] = missingPendingResourceAssertion['internal/api/node_commands_test.go'].replace(
    'wrongTargetResult.OK || !strings.Contains(wrongTargetResult.Error, "target")',
    'false',
  );
  if (!inspect(missingPendingResourceAssertion).some((issue) => issue.includes('uncertain node restart lacks wrong-resource/runtime rejection'))) {
    throw new Error('SOURCEONLY mutant control did not detect removed live-pending resource rejection');
  }

  const missingComfyFalse = { ...sources };
  missingComfyFalse['internal/api/node_commands_test.go'] = missingComfyFalse['internal/api/node_commands_test.go'].replace(
    'if target.SupportsAcceleratorReclaim {',
    'if false {',
  );
  if (!inspect(missingComfyFalse).some((issue) => issue.includes('native Comfy controller reclaim attempt is not denied before transition'))) {
    throw new Error('SOURCEONLY mutant control did not detect removed native Comfy false-capability assertion');
  }

  const duplicateGenericBoundary = { ...sources };
  duplicateGenericBoundary['internal/api/node_commands_test.go'] += '\nfunc TestControllerResidencySignedNodeBoundary(t *testing.T) { runControllerResidencySignedNodeBoundary(t) }\n';
  if (!inspect(duplicateGenericBoundary).some((issue) => issue.includes('only the Linux wrapper test declaration'))) {
    throw new Error('SOURCEONLY mutant control did not detect a duplicate generic/Linux boundary test');
  }

  const replayMutationEquality = { ...sources };
  replayMutationEquality['internal/api/node_commands_test.go'] = replayMutationEquality['internal/api/node_commands_test.go'].replace(
    'node.runtime.unloadCalls.Load() != beforeWarmReplayUnloads',
    'node.runtime.unloadCalls.Load() < beforeWarmReplayUnloads',
  );
  if (!inspect(replayMutationEquality).some((issue) => issue.includes('warm replay marker lacks exact before/after mutation equality'))) {
    throw new Error('SOURCEONLY mutant control did not detect a non-exact warm replay side-effect guard');
  }

  const missingComfyAttempt = { ...sources };
  missingComfyAttempt['internal/api/node_commands_test.go'] = missingComfyAttempt['internal/api/node_commands_test.go'].replace(
    'drainResult, drainErr := manager.DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")',
    'drainResult, drainErr := (*workloads.Manager)(nil).DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")',
  );
  if (!inspect(missingComfyAttempt).some((issue) => issue.includes('native Comfy controller reclaim attempt is not denied before transition'))) {
    throw new Error('SOURCEONLY mutant control did not detect removal of the real controller reclaim attempt');
  }

  const missingComfyDenial = { ...sources };
  missingComfyDenial['internal/api/node_commands_test.go'] = missingComfyDenial['internal/api/node_commands_test.go'].replace(
    'drainResult == nil || len(drainResult.TransitionIDs) != 0',
    'drainResult == nil',
  );
  if (!inspect(missingComfyDenial).some((issue) => issue.includes('native Comfy controller reclaim attempt is not denied before transition'))) {
    throw new Error('SOURCEONLY mutant control did not detect removal of native Comfy pre-transition denial assertion');
  }

  const missingLegacyComfyAlias = { ...sources };
  missingLegacyComfyAlias['internal/api/node_commands_test.go'] = missingLegacyComfyAlias['internal/api/node_commands_test.go'].replace(
    '\t\t\t\tboundaryEvent(t, "native_comfy_capability_false_zero_free")\n', '',
  );
  if (!inspect(missingLegacyComfyAlias).some((issue) => issue.includes('native Comfy denial markers are missing or precede'))) {
    throw new Error('SOURCEONLY mutant control did not detect a missing legacy Native Comfy marker alias');
  }

  const prematureLegacyComfyAlias = { ...sources };
  const legacyComfyMarker = '\t\t\t\tboundaryEvent(t, "native_comfy_capability_false_zero_free")\n';
  const comfyAttempt = '\t\t\t\tdrainResult, drainErr := manager.DrainNode(context.Background(), "node-a", "boundary", "native-comfy-forbidden-reclaim")\n';
  prematureLegacyComfyAlias['internal/api/node_commands_test.go'] = prematureLegacyComfyAlias['internal/api/node_commands_test.go']
    .replace(legacyComfyMarker, '')
    .replace(comfyAttempt, legacyComfyMarker + comfyAttempt);
  if (!inspect(prematureLegacyComfyAlias).some((issue) => issue.includes('native Comfy denial markers are missing or precede'))) {
    throw new Error('SOURCEONLY mutant control did not detect a legacy Native Comfy marker moved before measured denial');
  }

  const missingWebsocketLoadEvidence = { ...sources };
  missingWebsocketLoadEvidence['internal/api/node_commands_test.go'] = missingWebsocketLoadEvidence['internal/api/node_commands_test.go'].replace(
    'node.runtime.currentState() != "loaded" || node.runtime.loadCalls.Load() != beforeLoadCalls+1',
    'false',
  );
  if (!inspect(missingWebsocketLoadEvidence).some((issue) => issue.includes('controller load/unload markers lack exact runtime-state and HTTP side-effect evidence'))) {
    throw new Error('SOURCEONLY mutant control did not detect durable-row-only WebSocket load success');
  }

  const missingWebsocketUnloadEvidence = { ...sources };
  missingWebsocketUnloadEvidence['internal/api/node_commands_test.go'] = missingWebsocketUnloadEvidence['internal/api/node_commands_test.go'].replace(
    'node.runtime.currentState() != "unloaded" || node.runtime.unloadCalls.Load() != beforeUnloadCalls+1',
    'false',
  );
  if (!inspect(missingWebsocketUnloadEvidence).some((issue) => issue.includes('controller load/unload markers lack exact runtime-state and HTTP side-effect evidence'))) {
    throw new Error('SOURCEONLY mutant control did not detect durable-row-only WebSocket unload success');
  }

  console.log('SOURCEONLY: 8 owned paths inventoried; fabrication, pre-CAS publication, unresolved-switch, waiter, history-basis, zero-context, resident-result-fence, high-water-ticket/cancellation-commit fence, cancellation-without-live/projected/durable mutation, recovery/registration/replacement/retirement overflow, exhausted-route invalidation, VRAM invalidation, resident-slice alias, durable-HOT alias, blocker publication, complete profile-switch generation, residency generation, deterministic API barrier, bounded CAS-conflict submission, exact SENT/pending/no-admission guards, missing-test, websocket ticket-fence, lifecycle-claim, unique signed-boundary wrapper/helper, warm proof/replay equality, real PSI pressure path/refusal guard (including missing/wrong/disabled mutants), signed restart complete JSON comparison/marshal/time/schema/counter mutants, exact WebSocket runtime mutations, pending-query, measured Native Comfy denial, and legacy marker alias mutants rejected');
  console.log('SOURCEONLY: raw HTTP profile switch fails closed; public ticket API remains pending');
  console.log('SOURCEONLY: both result-CAS barrier cases use the existing manual pass-through fixture; barrier failure cleanup joins every started worker, releases both barriers before cancellation, and fail-closes before manager/server cleanup; fixture/worker/release/timeout/cleanup mutants rejected');
  console.log('runtime profile projection source controls passed');
}

const expected = new Map([
  ['vram-governor/internal/workloads', [
    'TestRuntimeProfileSchedulerSwitchesIdleTargetToSmallestSufficientProfile',
    'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence',
    'TestRuntimeProfilePendingRevokesOldVerifiedSlots',
    'TestRuntimeProfileReplayIdempotentGeneration',
    'TestLateResultCannotResurrectRetiredTarget',
    'TestRuntimeProfileObservationFailureStaysUnverified',
    'TestRuntimeProfileProjectionRejectsWrongNodeAndStaleGeneration',
    'TestRuntimeProfileSchedulerDoesNotSwitchWhileAcceleratorIsActive',
    'TestRuntimeProfileStaleResultCannotResurrectRetiredTarget',
    'TestRuntimeProfileUnresolvedTicketBlocksSecondPhysicalSwitch',
    'TestRuntimeProfileHistoryFailureWithholdsRegisteredCapacity',
    'TestRuntimeProfileHistoryRestoresOnlyKnownTerminalEvidence',
    'TestRuntimeProfileHistoryUsesLatestAcceptedAndRetainsUnresolved',
    'TestRuntimeProfileHistoryRejectsAmbiguousAcceptedOrdering',
    'TestRuntimeProfileUnknownEffectQuarantinesAlreadyRegisteredCardAliases',
    'TestRuntimeProfileTransitionWinsRegistrationHistoryRace',
    'TestRuntimeProfileDispatchFenceRequiresExactOriginatingTicket',
    'TestRuntimeProfileDispatchClaimExcludesRetirementAndRouteReplacement',
    'TestRuntimeProfileAcceptedHistoryIsScopedToPhysicalCardAndExactRoute',
    'TestRuntimeProfileHistoryReducerIsOrderIndependent',
    'TestRuntimeProfileRepeatedSwitchHistoryUsesPretransitionBasis',
    'TestRuntimeProfileZeroContextAdmissionCannotMutatePendingGeneration',
    'TestRuntimeProfileResultClaimFencesResidentGenerationMutation',
    'TestResidencyHighWaterRecoveryRejectsPendingProfileGeneration',
    'TestResidencyHighWaterRecoveryAdvancesSettledGenerationMonotonically',
    'TestResidencyHighWaterRecoveryRejectsMaxUint64BeforeLiveMutation',
    'TestTargetRegistrationPreservesExhaustedDurableGeneration',
    'TestRuntimeProfileTransitionRejectsInsufficientGenerationSpace',
    'TestRuntimeProfileHistoryRetryRestoresCapacityAndKeepsPendingAliasesBlocked',
    'TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts',
    'TestSetTargetResidentExhaustedRemovalDoesNotMutateLiveBackingSlice',
  ]],
  ['vram-governor/internal/api', [
    'TestRuntimeProfileProjectionBeforeWaiterAdmission',
    'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch',
    'TestRuntimeProfileRawHTTPAndWebsocketDispatchFailClosedWithoutCurrentTicket',
    'TestRegisterQuarantinesRuntimeCapacityAfterManagerRestart',
    'TestRuntimeProfileCommandGuardUsesAcceptedObservationForSucceededHistory',
    'TestRuntimeProfileCommandGuardRejectsAmbiguousAcceptedOrdering',
    'TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis',
  ]],
]);

const expectedSubtests = [
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/profile_id_only',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/missing_adapters',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/unverified',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/fallback_source',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/wrong_route',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/wrong_accelerator',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/missing_accelerator_index',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/negative_accelerator_index',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/missing_adapter_identity',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/missing_endpoint_identity',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/wrong_context',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/wrong_slots',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/wrong_profile',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/duplicate_target_observation',
  'TestRuntimeProfileSwitchRequiresObservedSlotsEvidence/duplicate_profile_observation',
  'TestRuntimeProfileProjectionRejectsWrongNodeAndStaleGeneration/wrong_node',
  'TestRuntimeProfileProjectionRejectsWrongNodeAndStaleGeneration/stale_generation',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/registration_before_result',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/registration_after_result',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/missing_observation',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/durable_result_CAS_conflict',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/late_known_completion',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/late_unknown_result',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/retirement_during_claimed_websocket_write',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/route_replacement_during_claimed_websocket_write',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/registration_waits_for_durable_result_commit',
  'TestRuntimeProfileProjectionBeforeWaiterAdmission/residency_high-water_writer_waits_for_result_projection',
  'TestRuntimeProfileDispatchClaimExcludesRetirementAndRouteReplacement/retirement_waits_for_claimed_physical_dispatch',
  'TestRuntimeProfileDispatchClaimExcludesRetirementAndRouteReplacement/route_replacement_waits_for_claimed_physical_dispatch',
  'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch/queued_before_send',
  'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch/sent_after_delivery_attempt',
  'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch/expired_without_delivery',
  'TestUnresolvedRuntimeProfileCommandGuardBlocksRepeatSwitch/failed_without_delivery',
  'TestRuntimeProfileHistoryRestoresOnlyKnownTerminalEvidence/accepted_success',
  'TestRuntimeProfileHistoryRestoresOnlyKnownTerminalEvidence/malformed_success',
  'TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts/changed_advertisement',
  'TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts/lower_VRAM_telemetry',
  'TestExhaustedLiveGenerationInvalidatesChangedAuthoritativeFacts/fresh_non-saturated_update',
  'TestRuntimeProfileHistoryUsesLatestAcceptedAndRetainsUnresolved/latest_accepted_observation',
  'TestRuntimeProfileHistoryUsesLatestAcceptedAndRetainsUnresolved/older_unresolved_effect_remains_blocking',
  'TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis/0',
  'TestRuntimeProfileRepeatedSchedulerSwitchesUsePretransitionHistoryBasis/1',
  'TestRuntimeProfileCommandGuardUsesAcceptedObservationForSucceededHistory/profile_id_only_legacy_success',
  'TestRuntimeProfileCommandGuardUsesAcceptedObservationForSucceededHistory/accepted_correlated_slot_observation',
];

function unitMode() {
  if (process.platform !== 'linux') throw new Error('--unit requires Linux; no test command was started');
  const version = spawnSync('go', ['version'], { encoding: 'utf8', windowsHide: true, timeout: 8_000 });
  if (version.error || version.status !== 0 || !/^go version go1\.23\.4 linux\/(?:amd64|arm64)\s*$/.test(version.stdout)) {
    throw new Error(`--unit requires exact Go 1.23.4 on Linux; observed ${version.stdout?.trim() || version.error?.message || 'unknown toolchain'}`);
  }

  const pkgPasses = new Map();
  let namedCount = 0;
  const diagnosticSites = zeroContextFailureSites(readOwned('internal/workloads/manager_test.go'));
  const highWaterDiagnosticSites = highWaterFailureSites(readOwned('internal/api/node_commands_test.go'));
  for (const [pkg, parents] of expected) {
    const names = new Set([...parents, ...expectedSubtests.filter((name) => name.startsWith(`${parents.find((parent) => name.startsWith(`${parent}/`)) || ''}/`))]);
    const parentPattern = `^(${parents.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})$`;
    const run = spawnSync('go', ['test', '-json', '-count=1', '-timeout=120s', '-run', parentPattern, `./${pkg.split('/').slice(1).join('/')}`], {
      cwd: root, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true, timeout: 130_000,
      env: { ...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off' },
    });
    if (run.error) throw new Error(`bounded Go test could not start for ${pkg}: ${run.error.message}`);
    if (run.status !== 0) {
      const diagnostic = failureOnlyGoTestDiagnostic(run.stdout, run.status, pkg, names, diagnosticSites, run.stderr, highWaterDiagnosticSites);
      if (diagnostic) process.stderr.write(diagnostic);
    }
    let parsed;
    try { parsed = parseGoTestStream(run.stdout, run.status, pkg, names); }
    catch { throw new Error(`bounded Go test stream failed strict validation for ${pkg}; event details suppressed`); }
    namedCount += parsed.namedCount;
    pkgPasses.set(pkg, parsed.packagePass);
  }
  console.log(`STRICT UNIT: exact uncached package PASS=${[...pkgPasses.keys()].sort().join(',')}`);
  console.log(`STRICT UNIT: exact unique RUN/PASS inventory=${namedCount}`);
  console.log('runtime profile projection unit controls passed');
}

try {
  const args = process.argv.slice(2);
  if (args.length !== 1 || !['--source', '--unit'].includes(args[0])) throw new Error('usage: node scripts/verify-runtime-profile-projection.mjs --source|--unit');
  if (args[0] === '--source') sourceMode();
  else unitMode();
} catch (error) {
  fail(error.message);
}
