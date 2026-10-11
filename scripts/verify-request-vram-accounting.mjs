#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const root = process.cwd();
const owned = [
  'internal/workloads/adapter.go',
  'internal/workloads/manager.go',
  'internal/workloads/manager_test.go',
  'internal/workloads/residency.go',
  'internal/workloads/residency_test.go',
  'scripts/verify-request-vram-accounting.mjs',
];
const names = [
  'TestRequestVRAMAccountingCountsEachProvenIncrementAndRejectsSlotNPlusOne',
  'TestRequestVRAMAccountingUnknownGenericEstimateFailsClosed',
  'TestRequestVRAMAccountingRejectsStaleOrWrongIdentityObservation',
  'TestRequestVRAMAccountingRejectsByteSumOverflow',
  'TestRequestVRAMAccountingInitializedProfilePoolIsChargedOnceWithinVerifiedBounds',
  'TestRequestVRAMAccountingCountsOtherTargetIncrementsOnSameAccelerator',
  'TestRequestVRAMAccountingSameModelOnDifferentRuntimeCountsBothFootprints',
  'TestRequestVRAMAccountingCountsActiveAllocationsWithoutHotResidency',
  'TestRequestVRAMAccountingUnknownPhysicalRequestWithoutBudgetFailsClosed',
  'TestRequestVRAMAccountingRejectsChangedVerifiedPoolBindings',
  'TestRequestVRAMAccountingThirdIncrementOverflowsWithThreeSlots',
];

function section(source, start, end) {
  const from = source.indexOf(start);
  if (from < 0) return '';
  const to = source.indexOf(end, from + start.length);
  return to < 0 ? source.slice(from) : source.slice(from, to);
}

function inspect(sources) {
  const issues = [];
  const adapter = sources['internal/workloads/adapter.go'];
  const manager = sources['internal/workloads/manager.go'];
  const managerTests = sources['internal/workloads/manager_test.go'];
  const residency = sources['internal/workloads/residency.go'];
  const reserve = section(manager, 'func (m *Manager) reserveTarget(', 'func (m *Manager) canCoScheduleLocked(');
  const placements = section(residency, '// Snapshot active requests under the placement fence', 'withReserve, err := addCapacityBytes');
  const capacity = section(residency, 'func (m *Manager) checkResidentCapacityExcluding(', 'func (m *Manager) validatePhysicalAcceleratorEnvelope(');
  const allocationKey = section(residency, 'func modelCapacityAllocationKey(', '\nfunc ');
  const validator = section(residency, 'func validateRequestVRAMIncrementObservation(', 'func multiResidentAdmissionConfigured(');
  const profileBound = section(residency, 'func (m *Manager) verifiedProfileCoversRequest(', 'func (m *Manager) validatePhysicalAcceleratorEnvelope(');

  if (!adapter.includes('type RequestVRAMIncrementObservation struct') ||
      !adapter.includes('type RequestVRAMIncrementObserver interface') ||
      !adapter.includes('ObserveRequestVRAMIncrement(context.Context, Target, domain.WorkloadRequest, Requirements)')) {
    issues.push('increment-observer-contract');
  }
  if (!reserve.includes('requestObserver, _ := m.adapters[target.Adapter].(RequestVRAMIncrementObserver)') ||
      !reserve.includes('requestObserver.ObserveRequestVRAMIncrement(ctx, target, workload.Request, requirements)') ||
      !reserve.includes('validateRequestVRAMIncrementObservation(observed, target, workload.Request.ID, requirements, targetGeneration') ||
      !reserve.includes('m.targetFenceMatches(target, targetGeneration)') ||
      !reserve.includes('placement.requestIncrementBytes = increment.Bytes') ||
      !reserve.includes('placement.requestIncrementVerified = true') ||
      /placement\.requestIncrementBytes\s*=\s*requirements\.EstimatedVRAMMB/.test(reserve) ||
      /placement\.requestIncrementBytes\s*=\s*placement\.vramMB/.test(reserve)) {
    issues.push('reserve-proof-provenance-and-generation-fence');
  }
  if (!validator.includes('observation.Verified') || !validator.includes('observation.Bytes < 0') ||
      !validator.includes('strings.HasPrefix(observation.Source, "runtime:")') ||
      !validator.includes('observation.TargetGeneration != generation') ||
      !validator.includes('observation.TargetID != target.ID') ||
      !validator.includes('observation.AcceleratorID != target.AcceleratorID') ||
      !validator.includes('observation.RequestID != requestID') ||
      !validator.includes('observation.Model != requirements.Model') ||
      !validator.includes('observation.ProfileID != target.ActiveRuntimeProfile') ||
      !validator.includes('observation.RuntimeIdentity != residencyCapacityIdentity(target)') ||
      !validator.includes('observation.ModelFingerprint != target.ModelFingerprint') ||
      !validator.includes('observation.ContextTokens != requirements.ContextTokens') ||
      !validator.includes('modelCapacityMaxAge')) {
    issues.push('observation-identity-freshness-and-units');
  }
  if (!capacity.includes('countedAllocations := make(map[string]modelContribution)') ||
      !capacity.includes('modelCapacityAllocationKey(capacity)') ||
      !capacity.includes('modelCapacityAllocationKey(requestedCapacity)') ||
      !allocationKey.includes('capacity.TargetID') ||
      !allocationKey.includes('capacity.Model') ||
      !allocationKey.includes('capacity.ProfileID') ||
      !allocationKey.includes('capacity.RuntimeIdentity') ||
      !allocationKey.includes('capacity.ModelFingerprint') ||
      !capacity.includes('prior := countedAllocations[allocationKey]') ||
      !capacity.includes('prior := countedAllocations[requestedAllocationKey]') ||
      !capacity.includes('requestedCapacity.FootprintBytes()') ||
      !capacity.includes('addCapacityBytes(usedVRAM, requestedVRAMBytes-prior.vram)') ||
      !capacity.includes('addCapacityBytes(usedVRAM, reserveVRAM)') ||
      !capacity.includes('m.verifiedProfileCoversRequest(placement, activeCapacity, footprintCharged)') ||
      !capacity.includes('activeCapacity, capacityErr := m.capacityForModel(ctx, activeTarget, placement.model)') ||
      !capacity.includes('countedAllocations[activeAllocationKey] = priorFootprint') ||
      !capacity.includes('footprintCharged := priorFootprint.vram > 0 || priorFootprint.ram > 0') ||
      !capacity.includes('activeTarget.ActiveRuntimeProfile != placement.profileID') ||
      !capacity.includes('m.targetGeneration(activeTarget.ID) != placement.targetGeneration') ||
      !capacity.includes('if !target.Cloud && target.AcceleratorID != "" && requested != ""') ||
      !capacity.includes('physical model request has no enforceable measured capacity budget')) {
    issues.push('single-model-footprint-and-reserve');
  }
  if (!placements.includes('if !placement.requestIncrementVerified') ||
      !placements.includes('if !m.verifiedProfileCoversRequest(placement, activeCapacity, footprintCharged) || profileSlots <= 0') ||
      !placements.includes('placement.requestIncrementBytes < 0') ||
      !placements.includes('placement.requestIncrementBytes)') ||
      !placements.includes('request increment is unknown and no verified initialized profile/slot/context bound covers workload') ||
      !placements.includes('poolUsers > poolSlots') ||
      placements.includes('excludeWorkloadID') ||
      placements.includes('continue // current request') ||
      !placements.includes('addCapacityBytes(usedVRAM, placement.requestIncrementBytes)') ||
      !placements.includes('addCapacityBytes(usedRAM, placement.requestIncrementBytes)')) {
    issues.push('all-active-increments-current-included-unknown-not-free');
  }
  if (!profileBound.includes('target.CapacityVerified') ||
      !profileBound.includes('target.CapacitySource != "runtime:/slots"') ||
      !profileBound.includes('target.ActiveRuntimeProfile != placement.profileID') ||
      !profileBound.includes('placement.contextTokens > target.ContextLimit') ||
      !profileBound.includes('profile.Slots == target.Slots') ||
      !profileBound.includes('profile.ContextLimit == target.ContextLimit') ||
      !profileBound.includes('capacity.ProfileBytes > 0') ||
      !profileBound.includes('m.targetGeneration(target.ID) != placement.targetGeneration')) {
    issues.push('verified-initialized-pool-profile-slot-context-fallback');
  }

  const testCounts = new Map(names.map((name) => [name, managerTests.split(`func ${name}(`).length - 1]));
  for (const [name, count] of testCounts) {
    if (count !== 1) issues.push(`named-manager-test:${name}:${count}`);
  }
  const poolTest = section(managerTests, 'func TestRequestVRAMAccountingInitializedProfilePoolIsChargedOnceWithinVerifiedBounds(', '\nfunc ');
  const exactTest = section(managerTests, 'func TestRequestVRAMAccountingCountsEachProvenIncrementAndRejectsSlotNPlusOne(', '\nfunc ');
  const crossTest = section(managerTests, 'func TestRequestVRAMAccountingCountsOtherTargetIncrementsOnSameAccelerator(', '\nfunc ');
  const aliasTest = section(managerTests, 'func TestRequestVRAMAccountingSameModelOnDifferentRuntimeCountsBothFootprints(', '\nfunc ');
  const activeTest = section(managerTests, 'func TestRequestVRAMAccountingCountsActiveAllocationsWithoutHotResidency(', '\nfunc ');
  const noBudgetTest = section(managerTests, 'func TestRequestVRAMAccountingUnknownPhysicalRequestWithoutBudgetFailsClosed(', '\nfunc ');
  const changedCapsTest = section(managerTests, 'func TestRequestVRAMAccountingRejectsChangedVerifiedPoolBindings(', '\nfunc ');
  const threeSlotTest = section(managerTests, 'func TestRequestVRAMAccountingThirdIncrementOverflowsWithThreeSlots(', '\nfunc ');
  const unknownTest = section(managerTests, 'func TestRequestVRAMAccountingUnknownGenericEstimateFailsClosed(', '\nfunc ');
  const profileSwitchTest = section(managerTests, 'func TestRuntimeProfileSchedulerSwitchesIdleTargetToSmallestSufficientProfile(', '\nfunc ');
  if (!exactTest.includes('mgr.reserveTarget(') || !exactTest.includes('checkResidentCapacityForWorkload') || !exactTest.includes('10 GiB') || !exactTest.includes('slots are busy')) {
    issues.push('manager-exact-N-and-N-plus-one-oracle');
  }
  if (!unknownTest.includes('EstimatedVRAMMB: 1') || !unknownTest.includes('increment is unknown') || !unknownTest.includes('requestIncrementVerified')) {
    issues.push('generic-estimate-negative-oracle');
  }
  if (!poolTest.includes('RuntimeProfiles: []RuntimeCapacityProfile') || !poolTest.includes('measuredCapacityWithProfile') || !poolTest.includes('checkResidentCapacityForWorkload')) {
    issues.push('initialized-pool-once-manager-oracle');
  }
  if (!crossTest.includes('shared physical accelerator placement') || !crossTest.includes('other target\'s distinct 1 GiB request increment')) {
    issues.push('cross-target-same-accelerator-manager-oracle');
  }
  if (!aliasTest.includes('different runtime identities were deduplicated') || !aliasTest.includes('same-model') || !aliasTest.includes('checkResidentCapacityForWorkload')) {
    issues.push('same-model-distinct-runtime-manager-oracle');
  }
  if (!activeTest.includes('ListModelResidencies') || !activeTest.includes('hot residency row unexpectedly exists') ||
      !activeTest.includes('measured increment') || !activeTest.includes('unknown increment') ||
      !activeTest.includes('measured resident capacity')) {
    issues.push('active-allocation-without-hot-row-manager-oracle');
  }
  if (!noBudgetTest.includes('AcceleratorID') || !noBudgetTest.includes('no enforceable measured capacity budget') ||
      !noBudgetTest.includes('reserveTarget(') || !noBudgetTest.includes('checkResidentCapacityForWorkload')) {
    issues.push('physical-no-budget-unknown-increment-negative');
  }
  if (!changedCapsTest.includes('context shrink') || !changedCapsTest.includes('profile change') ||
      !changedCapsTest.includes('generation change') || !changedCapsTest.includes('active physical allocation binding is stale')) {
    issues.push('changed-verified-context-profile-generation-negative');
  }
  if (!threeSlotTest.includes('Slots: 3') || !threeSlotTest.includes('three-slot') ||
      !threeSlotTest.includes('overflows int64') || !threeSlotTest.includes('third')) {
    issues.push('third-byte-overflow-with-three-slots-negative');
  }
  if (!profileSwitchTest.includes('fixturePhysicalBytes') || !profileSwitchTest.includes('8 << 30') ||
      !profileSwitchTest.includes('Capacity: fixtureEnvelope') ||
      !profileSwitchTest.includes('projectedCapacityTarget.ActiveRuntimeProfile =') ||
      !profileSwitchTest.includes('fixtureModelBytes') || !profileSwitchTest.includes('3 << 30') ||
      !profileSwitchTest.includes('fixtureInitializedProfilePoolBytes') || !profileSwitchTest.includes('2 << 30') ||
      !profileSwitchTest.includes('measuredCapacityWithProfile(projectedCapacityTarget') ||
      !profileSwitchTest.includes('backing.UpsertModelCapacity(ctx, &fixtureCapacity)') ||
      !profileSwitchTest.includes('defer mgr.Close()') ||
      !profileSwitchTest.includes('hasIncrementObserver := interface{}(adapter).(RequestVRAMIncrementObserver)') ||
      !profileSwitchTest.includes('projected.Capacity != fixtureEnvelope') ||
      !profileSwitchTest.includes('currentCapacity.RuntimeIdentity != residencyCapacityIdentity(projected)') ||
      !profileSwitchTest.includes('activePlacement.requestIncrementVerified || activePlacement.requestIncrementBytes != 0') ||
      !profileSwitchTest.includes('mgr.activePlacements[row.Request.ID]') ||
      !profileSwitchTest.includes('ctx32ProfileCount != 1')) {
    issues.push('profile-switch-synthetic-pool-binding-and-unknown-increment-fixture');
  }
  return issues;
}

function loadSources() {
  return Object.fromEntries(owned.map((relative) => [relative, readFileSync(path.join(root, relative), 'utf8')]));
}

function sourceControls() {
  const sources = loadSources();
  const baselineIssues = inspect(sources);
  if (baselineIssues.length) throw new Error(`source controls failed: ${baselineIssues.join(', ')}`);

  const mutants = [
    ['generic-estimate-as-increment', 'internal/workloads/manager.go', (s) => s.replace('placement.requestIncrementBytes = increment.Bytes', 'placement.requestIncrementBytes = requirements.EstimatedVRAMMB')],
    ['current-request-omission', 'internal/workloads/residency.go', (s) => s.replace('for _, placement := range placements {', 'for _, placement := range placements {\n\t\tif excludeWorkloadID != "" && placement.workloadID == excludeWorkloadID { continue }')],
    ['repeated-same-allocation-footprint', 'internal/workloads/residency.go', (s) => s.replace('prior := countedAllocations[allocationKey]', 'prior := modelContribution{}')],
    ['model-name-only-cross-runtime-dedup', 'internal/workloads/residency.go', (s) => s.replace('return strings.Join([]string{capacity.TargetID, capacity.Model, capacity.ProfileID, capacity.RuntimeIdentity, capacity.ModelFingerprint}, "\\x00")', 'return capacity.Model')],
    ['unknown-increment-as-zero', 'internal/workloads/residency.go', (s) => s.replace('if !m.verifiedProfileCoversRequest(placement, activeCapacity, footprintCharged) || profileSlots <= 0 {', 'if false {')],
    ['profile-cap-without-generation-fence', 'internal/workloads/residency.go', (s) => s.replace('m.targetGeneration(target.ID) != placement.targetGeneration', 'false')],
    ['active-allocation-footprint-omitted', 'internal/workloads/residency.go', (s) => s.replace('activeCapacity, capacityErr := m.capacityForModel(ctx, activeTarget, placement.model)', 'activeCapacity := requestedCapacity')],
    ['no-budget-physical-admission-bypass', 'internal/workloads/residency.go', (s) => s.replace('if !target.Cloud && target.AcceleratorID != "" && requested != "" {', 'if false {')],
    ['unknown-pool-not-required-to-be-charged', 'internal/workloads/residency.go', (s) => s.replace('footprintCharged := priorFootprint.vram > 0 || priorFootprint.ram > 0', 'footprintCharged := true')],
    ['profile-switch-fixture-budget-omitted', 'internal/workloads/manager_test.go', (s) => s.replace('Capacity: fixtureEnvelope,', 'Capacity: domain.CapacityBudget{},')],
    ['profile-switch-initialized-pool-fixture-omitted', 'internal/workloads/manager_test.go', (s) => s.replace('fixtureInitializedProfilePoolBytes int64 = 2 << 30', 'fixtureInitializedProfilePoolBytes int64 = 0')],
    ['profile-switch-active-placement-uses-workload-request-identity', 'internal/workloads/manager_test.go', (s) => s.replace('mgr.activePlacements[row.Request.ID]', 'mgr.activePlacements[row.ID]')],
    ['profile-switch-fabricated-increment-guard-omitted', 'internal/workloads/manager_test.go', (s) => s.replace('hasIncrementObserver := interface{}(adapter).(RequestVRAMIncrementObserver)', 'hasIncrementObserver := false')],
    ['profile-switch-manager-close-omitted', 'internal/workloads/manager_test.go', (s) => s.replace('defer mgr.Close()', '// fixture close omitted')],
  ];
  for (const [name, relative, mutate] of mutants) {
    const changed = { ...sources, [relative]: mutate(sources[relative]) };
    if (changed[relative] === sources[relative]) throw new Error(`mutant did not apply: ${name}`);
    const issues = inspect(changed);
    if (!issues.length) throw new Error(`source predicate accepted mutant: ${name}`);
  }
  return `source controls passed (${mutants.length} decisive source mutants; ${names.length} exact manager tests)`;
}

function unitControls() {
  const result = spawnSync('go', ['test', './internal/workloads', '-count=1', '-run', `^(${names.join('|')})$`, '-v'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120_000,
    maxBuffer: 4 * 1024 * 1024,
    windowsHide: true,
  });
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  if (result.error || result.status !== 0) throw new Error(`bounded unit command failed (status ${result.status ?? 'unknown'})`);
  const runNames = [...output.matchAll(/^=== RUN\s+(TestRequestVRAMAccounting[^\s/]+)\s*$/gm)].map((m) => m[1]);
  const passNames = [...output.matchAll(/^--- PASS:\s+(TestRequestVRAMAccounting[^\s/(]+)(?:\s|$)/gm)].map((m) => m[1]);
  if (/^--- (?:FAIL|SKIP):/m.test(output) || /^FAIL\s/m.test(output)) throw new Error('named accounting unit inventory contains a failure or skip');
  const exact = (actual) => actual.length === names.length && new Set(actual).size === names.length && names.every((name) => actual.includes(name));
  if (!exact(runNames) || !exact(passNames) || !/^ok\s+vram-governor\/internal\/workloads\s/m.test(output)) {
    throw new Error('named accounting unit RUN/PASS inventory mismatch');
  }
  return `unit controls passed (${names.length} exact uncached manager tests)`;
}

const args = process.argv.slice(2);
if (args.length !== 1 || !['--source', '--unit'].includes(args[0])) {
  console.error('usage: node scripts/verify-request-vram-accounting.mjs --source|--unit');
  process.exit(2);
}
try {
  const message = args[0] === '--source' ? sourceControls() : unitControls();
  console.log(`request VRAM accounting ${message}`);
} catch (error) {
  console.error(`request VRAM accounting failed: ${error instanceof Error ? error.message : 'unknown failure'}`);
  process.exitCode = 1;
}
