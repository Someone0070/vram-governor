import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const go = process.env.GO || 'go';
const goEnv = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'auto' };
const required = [
  'TestModelCapacityRoundTripPreservesExactInt64Bytes',
  'TestPostgresModelCapacityUpsertUsesOneTransaction',
  'TestMeasuredCapacityAdmissionUsesAggregateBytesAndHardCap',
  'TestCanonicalReserveCountedOnceAtExactBoundary',
  'TestEnsureModelResidentReclaimsAndRechecksMeasuredCapacityBoundaries',
  'TestEvictionCandidatesProtectActiveQueuedAndOperatorResidents',
  'TestCapacityIdentityAndFreshnessFailClosed',
  'TestPhysicalAcceleratorAggregateAcrossTargets',
  'TestConcurrentCapacityMeasurementsRemainBounded',
  'TestConcurrentAdmissionsOnSharedAcceleratorNeverOvercommit',
  'TestCheckedMiBConversionFailsClosedBeforeAdmission',
  'TestProductionSubmitCountsInFlightModelExactlyOnceAndOtherPlacement',
  'TestProductionMeasuredCapacityMatrixReclaimsAndChecksBoundaries',
  'TestProductionAdmissionRefreshInterleavingsReconcileWithoutColdStartOrDuplicateLoad',
  'TestReclaimForeignTargetsProtectsActiveQueuedPinnedManualAndOffResidents',
  'TestModelCapacityObservationRoundTripsIntoControllerStore',
  'TestModelCapacityObservationRejectsSpoofedAndStaleBindings',
  'TestMultiRowRuntimeObservationFailsNodeWireControllerWithoutStoreWrites',
  'TestDiscoverLlamaCPPPublishesOnlyAuthoritativePerModelCapacity',
  'TestDiscoverLlamaCPPSuppressesAmbiguousCapacityRowsButPreservesVisibility',
  'TestRetiredTargetDuringProfileCannotStartAndCleansReservation',
  'TestPowerProfileLateIdleSerializesBeforeNextActive',
  'TestRuntimeProfileStaleResultCannotResurrectRetiredTarget',
  'TestResidencyTransitionOmissionDuringCommandCannotCommitStaleResult',
  'TestReserveTargetLeaseDriftReleasesWithoutInMemoryResidue',
  'TestReserveTargetLeaseRollbackFailureRecordsReconciliationResidue',
  'TestTargetExecutionFingerprintCoversDispatchAndCapacityFacts',
  'TestResidencyGenerationCASRejectsStaleWrites',
];

function goRun(args, cwd = root) {
  const result = spawnSync(go, args, { cwd, env: goEnv, encoding: 'utf8', windowsHide: true });
  if (result.status !== 0) throw new Error(`go ${args.join(' ')} failed (status=${result.status})\n${result.stdout || ''}${result.stderr || ''}`);
  return result.stdout || '';
}

function jsonEvents(output) {
  return output.split(/\r?\n/).filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
}

function assertExecutedTests(output, names) {
  const events = jsonEvents(output);
  const passed = new Set(events.filter((event) => event.Action === 'pass' && event.Test).map((event) => event.Test));
  const skipped = new Set(events.filter((event) => event.Action === 'skip' && event.Test).map((event) => event.Test));
  const missing = names.filter((name) => !passed.has(name));
  assert.deepEqual(missing, [], `required scheduler tests did not execute and pass: ${missing.join(', ')}`);
  assert.deepEqual(names.filter((name) => skipped.has(name)), [], 'required scheduler tests were skipped');
}

function exactTestRun() {
  const pattern = `^(${required.join('|')})$`;
  const output = goRun(['test', './internal/store', './internal/workloads', './internal/api', './internal/nodeagent', '-run', pattern, '-count=1', '-json']);
  assertExecutedTests(output, required);
}

function capacityOracle(matrix) {
  assert.equal(matrix.length, 4, 'capacity oracle requires 10/16/24/32 GiB cases');
  for (const scenario of matrix) {
    const limit = scenario.gib * 1024 ** 3;
    const preReclaim = scenario.resident + scenario.requested + scenario.reserve;
    const postReclaim = scenario.requested + scenario.reserve;
    assert.ok(preReclaim > limit, `${scenario.gib} GiB over boundary did not exceed the measured envelope`);
    assert.ok(postReclaim <= limit, `${scenario.gib} GiB post-reclaim request does not fit`);
    const reclaimEligible = scenario.victimFootprint > 0 && !scenario.victimProtected;
    assert.equal(reclaimEligible, true, `${scenario.gib} GiB boundary must expose an eligible reclaim victim`);
    assert.ok(scenario.resident >= scenario.victimFootprint, `${scenario.gib} GiB victim is not part of resident footprint`);
  }
  return true;
}

function runScenarioOracleFixtures() {
  const reserve = 512 * 1024 ** 2;
  const requested = 4 * 1024 ** 3 + 1;
  const matrix = [10, 16, 24, 32].map((gib) => ({
    gib, reserve, requested, resident: gib * 1024 ** 3 - reserve - 4 * 1024 ** 3,
    victimFootprint: 4 * 1024 ** 3, victimProtected: false,
  }));
  capacityOracle(matrix);
  const unifiedLimit = 16 * 1024 ** 3;
  const unifiedModel = 4 * 1024 ** 3;
  const unifiedProfile = 128 * 1024 ** 2;
  const unifiedReserve = 512 * 1024 ** 2;
  const unifiedUsage = unifiedModel + unifiedProfile + unifiedReserve;
  assert.equal(unifiedUsage, 4 * 1024 ** 3 + 128 * 1024 ** 2 + 512 * 1024 ** 2, 'unified footprint arithmetic changed');
  assert.ok(unifiedUsage <= unifiedLimit, 'unified fit boundary is invalid');
  const unifiedOver = unifiedLimit - unifiedReserve - unifiedModel - unifiedProfile + 1;
  assert.ok(unifiedModel + unifiedProfile + unifiedOver + unifiedReserve > unifiedLimit, 'unified failing boundary is invalid');
  assert.equal(unifiedUsage, unifiedModel + unifiedProfile + unifiedReserve, 'unified memory double-counted model bytes into another budget');
  let reducedFailed = false;
  try { capacityOracle(matrix.slice(0, 3)); } catch { reducedFailed = true; }
  assert.equal(reducedFailed, true, 'reduced capacity matrix fixture unexpectedly passed');
}

function runBrokenGoFixtures() {
  const fixture = mkdtempSync(join(tmpdir(), 'scheduler-verifier-'));
  try {
    writeFileSync(join(fixture, 'go.mod'), 'module scheduler-verifier-fixture\n\ngo 1.21\n');
    writeFileSync(join(fixture, 'missing_test.go'), 'package fixture\nimport "testing"\nfunc TestPlaceholder(t *testing.T) {}\n');
    const pathTest = 'TestProductionMeasuredCapacityMatrixReclaimsAndChecksBoundaries';
    const missingOutput = goRun(['test', '-run', `^${pathTest}$`, '-count=1', '-json', '.'], fixture);
    assert.throws(() => assertExecutedTests(missingOutput, [pathTest]), /did not execute and pass/);
    writeFileSync(join(fixture, 'stub_test.go'), `package fixture\nimport "testing"\nfunc ${pathTest}(t *testing.T) { t.Skip("stub") }\n`);
    const stubOutput = goRun(['test', '-run', `^${pathTest}$`, '-count=1', '-json', '.'], fixture);
    assert.throws(() => assertExecutedTests(stubOutput, [pathTest]), /did not execute and pass|skipped/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

const implementation = readFileSync(resolve(root, 'internal/workloads/residency.go'), 'utf8') + readFileSync(resolve(root, 'internal/workloads/manager.go'), 'utf8');
if (/\b(?:cmp|3080|3090)\b/i.test(implementation)) throw new Error('scheduler contains product-name capacity branching');
const migration = readFileSync(resolve(root, 'migrations/0019_model_capacity.sql'), 'utf8');
for (const token of ['CREATE TABLE IF NOT EXISTS model_capacities', 'UNIQUE (target_id, model, profile_id)', 'ADD COLUMN IF NOT EXISTS revision', 'ADD COLUMN IF NOT EXISTS observed_at', 'runtime_identity']) assert.ok(migration.includes(token), `migration missing idempotent contract: ${token}`);
assert.equal(/\bDROP\s+(?:TABLE|COLUMN|DATABASE)\b/i.test(migration), false, 'capacity migration is destructive');
const cleanupMigration = readFileSync(resolve(root, 'migrations/0020_accelerator_lease_cleanup.sql'), 'utf8');
for (const token of ['CREATE TABLE IF NOT EXISTS accelerator_lease_cleanup_intents', 'PRIMARY KEY (accelerator_id, owner, fencing_token, workload_id)', 'next_retry_at', 'ALTER COLUMN workload_id SET NOT NULL']) assert.ok(cleanupMigration.includes(token), `cleanup migration missing idempotent contract: ${token}`);
assert.equal(/\bDROP\s+(?:TABLE|DATABASE)\b/i.test(cleanupMigration), false, 'cleanup migration is destructive');
assert.equal(/DROP\s+COLUMN\s+IF\s+EXISTS\s+(?!terminal_error\b|terminal_workload\b)/i.test(cleanupMigration), false, 'cleanup migration drops an unexpected column');

exactTestRun();
runScenarioOracleFixtures();
runBrokenGoFixtures();
console.log('multi-resident scheduler verification passed');
