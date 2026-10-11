import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const acceptance = fs.readFileSync(path.join(root, 'docs', 'acceptance.md'), 'utf8');
if (!acceptance.includes('migrations `0001` through `0020`') || !acceptance.includes('`0020_accelerator_lease_cleanup.sql`')) {
  throw new Error('acceptance matrix migration truth is stale; expected migrations 0001 through 0020');
}
const allowed = new Set(['--product-boundary']);
for (const argument of process.argv.slice(2)) {
  if (!allowed.has(argument)) throw new Error(`unsupported verifier argument: ${argument}`);
}

const tests = [
  'TestControllerAdapterRejectsUnavailableCapability',
  'TestControllerAdapterKnownBrokenCapabilityControl',
  'TestControllerAdapterUsesCanonicalIdentityAndFence',
  'TestControllerAdapterBoundsPollingAndCancellation',
  'TestControllerAdapterRejectsStaleResults',
  'TestControllerAdapterNodeReadinessAndSingleCardCeiling',
  'TestControllerAdapterVerifiesWarmObservation',
  'TestControllerAdapterRollsBackMismatch',
  'TestControllerAdapterRollbackFailureIsStructured',
  'TestControllerAdapterKnownPositiveBrokenWarmControl',
  'TestControllerAdapterDurableReplayRequiresExactObservation',
  'TestControllerAdapterPendingTransitionBlocksAfterRestart',
  'TestControllerAdapterReconcilesLateNodeResultBeforeNewCommand',
  'TestControllerAdapterRollbackRestoresAuthoritativeWarmFromTier',
  'TestResidencyTransitionIdempotencyRejectsCanonicalArgumentMismatch',
  'TestManagerKeepsIndeterminateResidencyTransitionForReconciliation',
  'TestControllerAdapterResourceQueriesIgnoreUnrelatedHistory',
  'TestResidencyAllocateConcurrentResourceFence',
  'TestLocalLLMInstantPerformanceIsAlwaysPublished',
  'TestLocalLLMInjectedClockReceivesRawTokensAcrossAllPaths',
  'TestClockSampleRejectsUTCReconstruction',
  'TestRouterModelStateTriStateAndMalformedEnvelope',
  'TestRouterModelStateRequiresByteExactStatus',
  'TestLlamaRouterTransitionalStateWaitsAndMalformedFails',
  'TestLlamaRouterMissingModelIsColdOnly',
];
const files = [
	'migrations/0018_workload_revision.sql',
	'migrations/0019_model_capacity.sql',
	'migrations/0020_accelerator_lease_cleanup.sql',
  'internal/workloads/adapters.go',
  'internal/workloads/adapters_test.go',
  'internal/workloads/warmram.go',
  'internal/workloads/warmram_test.go',
  'internal/workloads/residency.go',
  'internal/workloads/residency_test.go',
	'internal/api/node_commands_test.go',
	'internal/api/node_commands_linux_test.go',
	'internal/wsproto/messages_test.go',
];
for (const relative of files) {
  const filename = path.join(root, relative);
  if (!fs.existsSync(filename)) throw new Error(`missing controller adapter file: ${relative}`);
}
const source = files.map(relative => fs.readFileSync(path.join(root, relative), 'utf8')).join('\n');
for (const name of tests) {
  if (!source.includes(`func ${name}(`)) throw new Error(`required controller adapter test is absent: ${name}`);
}
// A known-positive broken control must be present before checking the secure
// absence assertions. This prevents source-only/zero-test certification.
if (!source.includes('TestControllerAdapterKnownBrokenCapabilityControl') || !source.includes('support alone')) {
  throw new Error('known-broken controller capability control is absent');
}

function run(args, options = {}) {
  const result = spawnSync('go', args, {cwd: root, encoding: 'utf8', ...options});
  if (result.status !== 0) throw new Error(`${args.join(' ')} failed\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}

const output = run(['test', './internal/workloads', '-count=1', '-json', '-run', `^(${tests.join('|')})$`]);
for (const name of tests) {
  if (!output.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"pass"'))) throw new Error(`required controller adapter test did not pass: ${name}`);
  if (output.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"skip"'))) throw new Error(`required controller adapter test was skipped: ${name}`);
}

// These are executable product-side oracles, not source-string controls. Keep
// them in the official verifier so deleting either read-only settlement or the
// Postgres transaction/CAS harness cannot still produce a green G2 token.
function requireGoTestPackage(pkg, name) {
  const result = run(['test', pkg, '-count=1', '-v', '-run', `^${name}$`]);
  if (!result.split('\n').some(line => line.includes(`--- PASS: ${name}`)) || result.split('\n').some(line => line.includes(`--- SKIP: ${name}`))) {
    throw new Error(`required executable oracle did not pass: ${pkg} ${name}`);
  }
}
requireGoTestPackage('./internal/nodeagent', 'TestReadOnlyQuerySettlesExactPendingMutation');
requireGoTestPackage('./internal/nodeagent', 'TestReadOnlyQueryRejectsPendingRuntimeIdentityDrift');
requireGoTestPackage('./internal/nodeagent', 'TestSignedQueryRejectsInventedOriginalLinkage');
requireGoTestPackage('./internal/nodeagent', 'TestQueryCannotSettleResidencyFromTierOnlyEvidence');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCachedAuthoritativeObservationReplayAllResidencyActions');
requireGoTestPackage('./internal/nodeagent', 'TestQuerySettlesExactInverseAsFailedForAllResidencyActions');
requireGoTestPackage('./internal/wsproto', 'TestResidencyCommandSchemaMatrix');
requireGoTestPackage('./internal/nodeagent', 'TestWarmIdentityDriftCloseFailurePersistsPendingAcrossRestartAndCleanupRetry');
requireGoTestPackage('./internal/nodeagent', 'TestNodeCommandRejectsTamperingAndUnknownActions');
requireGoTestPackage('./internal/nodeagent', 'TestLlamaRouterAbsentModelIsAuthoritativeUnloaded');
requireGoTestPackage('./internal/nodeagent', 'TestLlamaRouterRejectsMalformedNonmatchingEntry');
requireGoTestPackage('./internal/nodeagent', 'TestSignedUnloadAcceptsAbsentModelAsCold');
requireGoTestPackage('./internal/nodeagent', 'TestSignedLoadRejectsAbsentModelAfterMutation');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingLoadTransitionalRemainsPendingAfterRestart');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingWarmTransitionalRemainsPendingAfterRestart');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingPersistsCanonicalReplayForAllResidencyActions');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingRejectsManifestOperationMismatch');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingManifestMismatchMatrix');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingRejectsCachedResultEnvelopeDrift');
requireGoTestPackage('./internal/nodeagent', 'TestReconcilePendingJournalCrashReplaysWithoutMutation');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCachedMutationReplayRejectsAliasBindingAndProofDrift');
requireGoTestPackage('./internal/nodeagent', 'TestCachedAuthoritativeObservationRejectsAliasBindingAndProofDrift');
requireGoTestPackage('./internal/nodeagent', 'TestCachedLegacyMutationReplayExactHotColdSchema');
requireGoTestPackage('./internal/nodeagent', 'TestResidencyCacheLegacyCurrentBranchMatrix');
requireGoTestPackage('./internal/nodeagent', 'TestLiveHandleCanonicalResidencyQueryMatrixAllActions');
requireGoTestPackage('./internal/nodeagent', 'TestLiveHandleAllEightResidencyActionsDurableMatrix');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCachedResidencyDriftFailsClosedLiveCausal');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCachedReplayRejectsLiveCapabilityContextDrift');
requireGoTestPackage('./internal/nodeagent', 'TestHandleLegacyCacheRejectsMismatchedFenceProof');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCurrentCacheRejectsSlotsProofLossAndChange');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCurrentCacheRejectsRemovedAndDisabledRuntimeTargets');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCurrentCacheRejectsMixedInvalidSlotsForMutationAndQuery');
requireGoTestPackage('./internal/nodeagent', 'TestSignedLlamaCPPCommandRejectsPassiveRuntimeLifecycle');
requireGoTestPackage('./internal/nodeagent', 'TestLlamaSlotsRejectsMalformedRowsAndMixedCapacity');
requireGoTestPackage('./internal/nodeagent', 'TestDiscoverLlamaCPPMixedSlotsNeverVerifiesCapacity');
requireGoTestPackage('./internal/nodeagent', 'TestDiscoverLlamaCPPPassiveStatusDoesNotAdvertiseLifecycle');
requireGoTestPackage('./internal/nodeagent', 'TestDiscoverLlamaCPPUsesRuntimeContextAndSlots');
requireGoTestPackage('./internal/nodeagent', 'TestDiscoverLlamaCPPUsesOllamaRunningModelsForResidency');
requireGoTestPackage('./internal/nodeagent', 'TestHandleCachedSuccessNeverBypassesBlockedResidencyState');
requireGoTestPackage('./internal/api', 'TestPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController');
requireGoTestPackage('./internal/api', 'TestWireCapabilityValidationPreservesVerifiedFalseTargetCapabilities');
requireGoTestPackage('./internal/workloads', 'TestObserveResidencyResultExactActionTierProofSchema');
requireGoTestPackage('./internal/workloads', 'TestControllerAdapterAllResidencyActionsCurrentEnvelope');
requireGoTestPackage('./internal/workloads', 'TestControllerAdapterAllResidencyActionsDispatchesThroughTransition');
requireGoTestPackage('./internal/workloads', 'TestControllerAdapterAllResidencyActionsDispatchSchemaNegatives');
requireGoTestPackage('./internal/api', 'TestAdminQueryRequiresDurableOriginalCommandLinkage');
requireGoTestPackage('./internal/store', 'TestDeterministicPostgresResidencyAndNodeCASHarness');
requireGoTestPackage('./internal/store', 'TestDeterministicPostgresBudgetClaimSettleReleaseConcurrency');
requireGoTestPackage('./internal/store', 'TestDeterministicPostgresReserveAndLinkBudgetClaimAtomic');
requireGoTestPackage('./internal/store', 'TestMemoryNodeCommandRecoveryAdvancePersistsFutureDueAfterReload');
requireGoTestPackage('./internal/store', 'TestLegacyWorkloadRevisionRequiresFirstAtomicClaim');
requireGoTestPackage('./internal/store', 'TestBudgetClaimTokenPreventsLosingCleanup');
requireGoTestPackage('./internal/store', 'TestWorkloadRevisionMigrationBackfillsLegacyJSONAtomically');
requireGoTestPackage('./internal/store', 'TestWorkloadRevisionMigrationFixtureMatrix');
requireGoTestPackage('./internal/api', 'TestAdminNodeCommandUncertainReplayUsesQueryRecovery');
requireGoTestPackage('./internal/api', 'TestAdminNodeCommandUsesCanonicalResidencyEnvelope');
requireGoTestPackage('./internal/api', 'TestAdminNodeCommandRejectsIrrelevantResidencyArgs');
requireGoTestPackage('./internal/api', 'TestSupersededNodeSessionCannotMutateOrSend');
requireGoTestPackage('./internal/api', 'TestDelayedLowerGenerationRegistrationHasNoStoreSideEffect');
requireGoTestPackage('./internal/api', 'TestSessionMutationAndReplacementInterleaveWithoutDeadlock');
requireGoTestPackage('./internal/api', 'TestServerCloseTracksPreRegisterWebsocket');
requireGoTestPackage('./internal/api', 'TestRecoveryTimerReplacementIdentityAndFutureClose');
requireGoTestPackage('./internal/api', 'TestNodeConnectionWriteGateHonorsContextAndClose');
requireGoTestPackage('./internal/api', 'TestNodeConnectionRealBackpressureCloseAndGateReuse');
requireGoTestPackage('./internal/api', 'TestProductionWebsocketRestartAndCommandReplay');
requireGoTestPackage('./internal/api', 'TestControllerRejectsForgedAuthoritativeObservation');
requireGoTestPackage('./internal/api', 'TestControllerResidencyInverseEvidenceAllActions');
requireGoTestPackage('./internal/api', 'TestControllerResidencyInverseSettleUncertainAllActions');
requireGoTestPackage('./internal/api', 'TestControllerResidencySettleRejectsBindingAndProofDrift');
requireGoTestPackage('./internal/api', 'TestCapabilityRefreshRejectsNoncanonicalCapacityFields');
requireGoTestPackage('./internal/api', 'TestCapabilitiesPayloadRejectsNoncanonicalTopLevelAndNullSafetyFields');
requireGoTestPackage('./internal/api', 'TestCapabilitiesPayloadRejectsNestedAdapterAndProfileAliases');
requireGoTestPackage('./internal/api', 'TestRegisterPayloadStrictlyRejectsUnknownAndNullNestedFields');
requireGoTestPackage('./internal/api', 'TestRegisterRejectsInvalidNestedAdapterBeforeStore');
requireGoTestPackage('./internal/workloads', 'TestInitialTargetObservationFailureIsRetriedDurably');
requireGoTestPackage('./internal/workloads', 'TestOlderTargetObservationCannotDeleteNewerRetry');
requireGoTestPackage('./internal/workloads', 'TestCancelledResidencyObserverCannotOverwriteNewerFacts');
requireGoTestPackage('./internal/workloads', 'TestWorkloadRevisionCASAndCancellationOwnership');
requireGoTestPackage('./internal/workloads', 'TestWorkloadMutationCASCancellationRaceSeeded');
requireGoTestPackage('./internal/workloads', 'TestFullWorkloadProjectionNeverOverwritesNewerSameStatusFields');
requireGoTestPackage('./internal/workloads', 'TestCancellationOwnerRetryIsIdempotentAndForeignOwnerConflicts');
requireGoTestPackage('./internal/workloads', 'TestOlderMissingResidencyCannotOverwriteNewerCreate');
requireGoTestPackage('./internal/workloads', 'TestResidencyObservationPreservesNewerWarmTransition');
requireGoTestPackage('./internal/workloads', 'TestResidencyTierNormalizationRequiresWarmProofAndClearsIncompatibleClaims');
requireGoTestPackage('./internal/workloads', 'TestBudgetSideEffectsAreIntentBeforeCrashSafe');
requireGoTestPackage('./internal/workloads', 'TestManagerCloseCancelsExecutionAndRejectsRestart');
requireGoTestPackage('./internal/workloads', 'TestProjectionRepairFailureRetainsSucceededPendingEvidence');
requireGoTestPackage('./internal/workloads', 'TestRuntimeCacheReclaimObservationUnavailableRemainsRecoverable');
requireGoTestPackage('./internal/workloads', 'TestNativeComfyReclaimRejectedBeforeSideEffect');
requireGoTestPackage('./internal/workloads', 'TestLegacyUnobservableReclaimIsDiscoverableForManualReconciliation');
requireGoTestPackage('./internal/workloads', 'TestRunStreamCloseWaitsForExecutionUnwind');
requireGoTestPackage('./internal/workloads', 'TestPendingStreamTimerStopFalseRetainsCloseOwnership');
requireGoTestPackage('./internal/store', 'TestReserveAndLinkBudgetClaimIsAtomic');
requireGoTestPackage('./internal/store', 'TestTerminalBudgetCASRequiresSettlementIntent');

function runPostgresMigrationFixture() {
  // The executable deterministic transaction harness above is the portable
  // oracle. Run the live PostgreSQL 16 fixture only when an operator has
  // explicitly supplied a database requirement; a missing local service is
  // an environment state, not permission to fabricate live evidence.
  if (process.env.VRAM_REQUIRE_LIVE_POSTGRES !== '1' && !process.env.DATABASE_URL && !process.env.PGHOST) {
    console.log('live PostgreSQL migration fixture skipped (no DSN)');
    return;
  }
  const migration = path.join(root, 'migrations', '0018_workload_revision.sql').replaceAll('\\', '/');
  const wslMigration = `/mnt/${migration[0].toLowerCase()}${migration.slice(2)}`;
  const sql = `
CREATE TEMP TABLE workloads(id text primary key, body jsonb, status text not null, updated_at timestamptz not null default now());
CREATE TEMP TABLE budget_reservations(workload_id text primary key, body jsonb not null, status text not null, updated_at timestamptz not null default now());
INSERT INTO workloads(id,body,status) VALUES
 ('keep','{"revision":9,"budget_reservation_token":"keep-token"}','queued'),
 ('missing','{}','waiting'), ('partial','{"revision":5}','running'), ('mismatch','{"revision":2,"budget_reservation_token":"stale-token"}','succeeded'), ('terminal-missing','{"error":"history"}','failed');
INSERT INTO budget_reservations(workload_id,body,status) VALUES
 ('keep','{"revision":4,"attempt":7,"ownership_token":"reservation-token"}','reserved'),
 ('missing','{"attempt":8}','reserved'), ('partial','{"revision":3,"ownership_token":"partial-token"}','reserved'),
 ('mismatch','{"revision":2,"attempt":4,"ownership_token":"authoritative-token"}','reserved'),
 ('terminal-history','{"history":"keep","revision":8,"attempt":4,"ownership_token":"terminal-token"}','settled');
\\i '${wslMigration.replaceAll("'", "''")}'
\\i '${wslMigration.replaceAll("'", "''")}'
SELECT id || ':' || body::text FROM workloads ORDER BY id;
SELECT workload_id || ':' || body::text FROM budget_reservations ORDER BY workload_id;
`;
  const distro = process.env.NODE_RESIDENCY_WSL_DISTRO || 'Ubuntu';
  const command = process.platform === 'win32' ? 'wsl.exe' : 'psql';
  const args = process.platform === 'win32' ? ['-d', distro, '--', 'psql', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'] : ['-d', 'postgres', '-v', 'ON_ERROR_STOP=1'];
  const result = spawnSync(command, args, {cwd: root, encoding: 'utf8', input: sql});
  if (result.status !== 0) throw new Error(`PostgreSQL 16 migration fixture failed\n${result.stdout}\n${result.stderr}`);
  const output = result.stdout;
  for (const expected of [
    'keep:{"revision": 9, "budget_reservation_token": "reservation-token", "budget_reservation_attempt": 7}',
    'missing:{"revision": 1, "budget_reservation_token":',
    'partial:{"revision": 5, "budget_reservation_token": "partial-token", "budget_reservation_attempt": 1}',
    'terminal-missing:{"error": "history", "revision": 1}',
    'mismatch:{"revision": 2, "budget_reservation_token": "stale-token"}',
    'keep:{"attempt": 7, "revision": 4, "ownership_token": "reservation-token"}',
    'missing:{"attempt": 8, "revision": 1, "ownership_token":',
    'partial:{"attempt": 1, "revision": 3, "ownership_token": "partial-token"}',
    'terminal-history:{"attempt": 4, "history": "keep", "revision": 8, "ownership_token": "terminal-token"}',
  ]) if (!output.includes(expected)) throw new Error(`PostgreSQL migration fixture lost expected field: ${expected}\n${output}`);
}
runPostgresMigrationFixture();
const livePostgresConfigured = process.env.VRAM_REQUIRE_LIVE_POSTGRES === '1' || Boolean(process.env.DATABASE_URL || process.env.PGHOST);
console.log(livePostgresConfigured
  ? 'deterministic PostgreSQL transaction semantics harness passed; live migration fixture passed'
  : 'deterministic PostgreSQL transaction semantics harness passed; live migration fixture skipped (no DSN)');

const boundaryTests = ['TestControllerResidencySignedNodeBoundary', 'TestControllerNativeComfyBoundaryIsFailClosed'];
const boundaryPattern = boundaryTests.join('|');
function runLinuxBoundary() {
  if (process.platform !== 'win32') {
    return run(['test', './internal/api', '-count=1', '-json', '-run', `^(${boundaryPattern})$`]);
  }
  const binary = path.join(root, '.controller-api-linux.test');
  const temp = path.join(root, '.controller-boundary-tmp');
  const cache = path.join(root, '.controller-boundary-cache');
  fs.mkdirSync(temp, {recursive: true});
  fs.mkdirSync(cache, {recursive: true});
  try {
    const build = spawnSync('go', ['test', '-c', '-o', binary, './internal/api'], {
      cwd: root,
      encoding: 'utf8',
      env: {...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0', GOTMPDIR: temp, GOCACHE: cache},
    });
    if (build.status !== 0) throw new Error(`linux boundary cross-build failed\n${build.stdout}\n${build.stderr}`);
    const drive = root[0].toLowerCase();
    const wslRoot = `/mnt/${drive}${root.slice(2).replaceAll('\\', '/')}`;
    const distro = process.env.NODE_RESIDENCY_WSL_DISTRO || 'Ubuntu';
    const command = `cd '${wslRoot.replaceAll("'", "'\\''")}' && './.controller-api-linux.test' -test.run '^(${boundaryPattern})$' -test.v -test.count=1`;
    const result = spawnSync('wsl.exe', ['-d', distro, '--', 'bash', '-lc', command], {cwd: root, encoding: 'utf8'});
    if (result.status !== 0) throw new Error(`linux boundary execution failed\n${result.stdout}\n${result.stderr}`);
    return result.stdout;
  } finally {
    for (const filename of [binary]) {
      try { fs.rmSync(filename, {force: true}); } catch {}
    }
    for (const directory of [temp, cache]) {
      try { fs.rmSync(directory, {recursive: true, force: true}); } catch {}
    }
  }
}
const boundaryOutput = runLinuxBoundary();
if (process.platform === 'win32') {
  for (const name of boundaryTests) if (!boundaryOutput.includes(`--- PASS: ${name}`)) throw new Error(`required signed controller/node boundary test did not pass: ${name}`);
  if (!boundaryOutput.includes('\nPASS')) throw new Error('required signed controller/node boundary tests did not pass');
} else {
  for (const name of boundaryTests) {
    if (!boundaryOutput.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"pass"'))) throw new Error(`required signed controller/node boundary test did not pass: ${name}`);
    if (boundaryOutput.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"skip"'))) throw new Error(`required signed controller/node boundary test was skipped: ${name}`);
  }
}
for (const event of ['load_hot', 'unload_cold', 'warm_verified', 'warm_replay_exact', 'cleanup_cold', 'late_result_reconciled', 'restart_replay_exact', 'node_handle_replay_exact', 'controller_restart_replay_exact', 'signed_expiry_zero_mutation', 'uncertain_restart_query_first', 'uncertain_intent_reconciled', 'live_pending_wrong_resource_rejected', 'live_pending_runtime_identity_rejected', 'stale_rejected', 'envelope_rejected', 'empty_capability_rejected', 'query_authoritative', 'rollback_observed', 'mismatch_rollback_observed', 'offline_rejected', 'native_comfy_capability_false_zero_free']) {
  if (!boundaryOutput.includes(`boundary pass: ${event}`)) {
    throw new Error(`required real boundary event was not observed: ${event}`);
  }
}

if (process.argv.includes('--product-boundary')) {
  console.log('node-controller residency integration passed');
} else {
  console.log('controller residency adapter verification passed');
}
