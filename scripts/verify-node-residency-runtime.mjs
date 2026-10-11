import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const knownArguments = new Set(['--linux-cross-build', '--controller-adapter']);
for (const argument of process.argv.slice(2)) {
  if (!knownArguments.has(argument)) throw new Error(`unsupported verifier argument: ${argument}`);
}
const commandTests = [
  'TestSignedModelCommandIsAllowlistedAndDurablyIdempotent',
  'TestNodeCommandRejectsIdempotencyKeyReuse',
  'TestComfyReclaimRequiresAuthoritativeStatus',
  'TestCommandStateRejectsCorruptionAndRequiresReconciliation',
  'TestDurableStateBlockSurvivesWarmReconcile',
  'TestCommandStatePersistenceFailuresRemainBlocked',
  'TestRecoveryEpochPreservesFenceAndCompletedResult',
  'TestRecoveryMarkerPhasesAndIdentityBinding',
  'TestPrimaryAndMarkerFailureLeavesPriorPendingAndNoRuntimeMutation',
  'TestRecoveryMarkerPersistenceInjectionLeavesPriorStateBlocked',
  'TestStartupRecoveryGenerationIsMonotonicAndAuditMarkerRemains',
  'TestAgentRefusesControllerOnStartupRecoveryInitializationFailure',
  'TestAgentHeartbeatReportsNotReadyForDurableBlock',
  'TestRecoveryEpochHistoryIsCompleteBeyondLegacyBound',
  'TestPreparedRecoveryResumesWithoutImportingProposedState',
  'TestStateJournalRejectsPrimaryRollbackAfterLaterSave',
  'TestStartupCleanupIntentNeverRepinsWarmManifest',
  'TestSignedReverifyRejectsNonUnloadedRuntimeStates',
  'TestSignedReverifyValidationCloseFailureRetainsPendingAcrossRestart',
  'TestReconnectReconcileReducedBudgetPreservesRecency',
  'TestLifecycleFencingRequiresExactInteger',
  'TestRuntimeErrorsRedactExternalSecrets',
  'TestSignedWarmCleanupIsIdempotentAndTargetScoped',
  'TestRuntimeManifestFingerprintExcludesMutableResidencyStatus',
  'TestLlamaModelStatusRequiresAuthoritativeString',
  'TestLlamaRouterAbsentModelIsAuthoritativeUnloaded',
  'TestLlamaRouterRejectsMalformedNonmatchingEntry',
  'TestSignedUnloadAcceptsAbsentModelAsCold',
  'TestSignedLoadRejectsAbsentModelAfterMutation',
  'TestReconcilePendingLoadTransitionalRemainsPendingAfterRestart',
  'TestReconcilePendingWarmTransitionalRemainsPendingAfterRestart',
  'TestReconcilePendingPersistsCanonicalReplayForAllResidencyActions',
  'TestReconcilePendingRejectsManifestOperationMismatch',
  'TestReconcilePendingManifestMismatchMatrix',
  'TestReconcilePendingRejectsCachedResultEnvelopeDrift',
  'TestReconcilePendingJournalCrashReplaysWithoutMutation',
  'TestResourceFenceMonotonicAndCollisionFree',
  'TestPartialResourceIntentRetainedAfterSideEffectError',
  'TestPreflightFailuresDoNotRetainPendingOrBlock',
  'TestLegacyPrimaryWithExistingJournalIsBlocked',
  'TestMissingPrimaryWithJournalOrMarkerIsBlocked',
  'TestBlockedProcessorDoesNotReplayCachedSuccess',
  'TestProductFenceRejectsLowerRuntimeProfileTokenAcrossAliases',
  'TestProductFenceRejectsLowerGPUProfileToken',
  'TestProductionFenceKeysKeepCollisionShapedModelTargetsDistinct',
  'TestRestoredWarmManifestBlocksReadinessUntilReconciled',
  'TestCommandBlockingDoesNotBlockHeartbeatReadiness',
  'TestCommandReplayAndMismatchPreserveReadiness',
  'TestNodeCommandRejectsTamperingAndUnknownActions',
  'TestStrictResidencyEnvelopeRejectsIrrelevantCrossActionArgs',
  'TestReadOnlyQuerySettlesExactPendingMutation',
  'TestReadOnlyQueryRejectsPendingRuntimeIdentityDrift',
  'TestSignedQueryRejectsInventedOriginalLinkage',
  'TestQueryCannotSettleResidencyFromTierOnlyEvidence',
  'TestHandleCachedAuthoritativeObservationReplayAllResidencyActions',
  'TestCachedLegacyMutationReplayExactHotColdSchema',
  'TestResidencyCacheLegacyCurrentBranchMatrix',
  'TestLiveHandleCanonicalResidencyQueryMatrixAllActions',
  'TestLiveHandleAllEightResidencyActionsDurableMatrix',
  'TestHandleCachedResidencyDriftFailsClosedLiveCausal',
  'TestHandleCachedReplayRejectsLiveCapabilityContextDrift',
  'TestHandleLegacyCacheRejectsMismatchedFenceProof',
  'TestHandleCurrentCacheRejectsSlotsProofLossAndChange',
  'TestHandleCurrentCacheRejectsRemovedAndDisabledRuntimeTargets',
  'TestHandleCurrentCacheRejectsMixedInvalidSlotsForMutationAndQuery',
  'TestSignedLlamaCPPCommandRejectsPassiveRuntimeLifecycle',
  'TestLlamaSlotsRejectsMalformedRowsAndMixedCapacity',
  'TestDiscoverLlamaCPPMixedSlotsNeverVerifiesCapacity',
  'TestDiscoverLlamaCPPPassiveStatusDoesNotAdvertiseLifecycle',
  'TestDiscoverLlamaCPPUsesRuntimeContextAndSlots',
  'TestDiscoverLlamaCPPUsesOllamaRunningModelsForResidency',
  'TestHandleCachedSuccessNeverBypassesBlockedResidencyState',
  'TestCachedAuthoritativeObservationRejectsAliasBindingAndProofDrift',
  'TestLivePendingWrongResourceQueryThroughHandle',
  'TestLivePendingRuntimeIdentityDriftThroughHandle',
  'TestWarmIdentityDriftCloseFailurePersistsPendingAcrossRestartAndCleanupRetry',
  'TestWarmCommandFailedLRUVictimCleanupRestoresReadiness',
];
const warmTests = [
  'TestWarmRAMKnownBrokenControl',
  'TestWarmRAMInjectedBackendVerifiesIdentityAndCleanup',
  'TestWarmRAMDeterministicPressureRollbackAndCleanup',
  'TestWarmRAMPlatformNeutralParsersFailClosed',
  'TestWarmRAMRejectsPageCacheWithLockedBytes',
  'TestWarmRAMRejectsUnlockedBytesWithValidOracle',
  'TestWarmRAMTargetScopedIdentityAndReverification',
  'TestWarmRAMLastUsedPersistsDeterministicLRUVictim',
  'TestWarmRAMRejectsNonCanonicalAndPressure',
  'TestWarmRAMRefusesObservedOOMPressure',
  'TestWarmRAMUnsupportedFailsClosed',
  'TestWarmRAMHotReloadInvalidatesWarmClaim',
  'TestWarmRAMHeadroomDoesNotDoubleCountExistingPinnedBytes',
  'TestWarmRAMIdentityDriftCloseFailureRetainsCleanupHandle',
  'TestWarmRAMReverifyIdentityDriftCloseFailureRetainsCleanupHandle',
  'TestWarmRAMValidationCloseFailureRetainsCleanupHandle',
  'TestWarmRAMLRUCloseFailureInvokesSideEffectAndRetainsVictim',
];
const controllerTests = [
  'TestNodeRegistrationReadinessIsPersistedBeforeHeartbeat',
  'TestLegacyNodeRegistrationReadinessOmittedPreservesCompatibility',
  'TestNodeRegistrationStoreFailureSendsNoAckOrConnection',
  'TestHeartbeatReadinessDowngradePersistsNonReadyLifecycle',
  'TestHeartbeatStoreFailureDoesNotAcknowledgeOrKeepConnection',
  'TestSupersededNodeSessionCannotMutateOrSend',
  'TestAdminNodeCommandUncertainReplayUsesQueryRecovery',
  'TestAdminQueryRequiresDurableOriginalCommandLinkage',
  'TestDelayedLowerGenerationRegistrationHasNoStoreSideEffect',
  'TestSessionMutationAndReplacementInterleaveWithoutDeadlock',
  'TestServerCloseTracksPreRegisterWebsocket',
  'TestRecoveryTimerReplacementIdentityAndFutureClose',
  'TestControllerRejectsForgedAuthoritativeObservation',
  'TestWireCapabilityValidationPreservesVerifiedFalseTargetCapabilities',
  'TestPassiveLlamaAdvertisementRoundTripsFalseLifecycleThroughController',
  'TestRegisterRejectsInvalidNestedAdapterBeforeStore',
];
const files = [
  'internal/nodeagent/commands.go', 'internal/nodeagent/llamacpp.go', 'internal/nodeagent/llamacpp_test.go',
  'internal/nodeagent/warmram.go', 'internal/nodeagent/warmram_linux.go',
  'internal/nodeagent/warmram_other.go', 'internal/nodeagent/warmram_test.go',
  'internal/nodeagent/commands_test.go',
  'internal/wsproto/messages_test.go',
  'internal/api/ws.go', 'internal/api/ws_test.go',
  'internal/api/workloads_http_test.go',
];
for (const relative of files) {
  if (!fs.existsSync(path.join(root, relative))) throw new Error(`missing runtime file: ${relative}`);
}
const source = files.map(relative => fs.readFileSync(path.join(root, relative), 'utf8')).join('\n');
for (const name of [...commandTests, ...warmTests, ...controllerTests]) {
  if (!source.includes(`func ${name}(`)) throw new Error(`required product-backed test is absent: ${name}`);
}
// Known-positive broken control: ordinary page-cache language/oracles must not
// be enough to certify warm bytes. This check runs before the absence check so
// an accidentally weakened verifier cannot pass with zero matches.
if (!source.includes('TestWarmRAMKnownBrokenControl') || !source.includes('page-cache')) {
  throw new Error('known-broken page-cache control is absent');
}
// The named control is executed below; do not treat source text as the oracle.

function run(args, env = process.env) {
  const result = spawnSync('go', args, {cwd: root, env, encoding: 'utf8'});
  if (result.status !== 0) throw new Error(`${args.join(' ')} failed\n${result.stdout}\n${result.stderr}`);
  return result.stdout;
}
const adapterIndex = process.argv.indexOf('--controller-adapter');
if (adapterIndex >= 0) {
  const controller = spawnSync(process.execPath, [path.join(root, 'scripts', 'verify-controller-residency-adapter.mjs'), '--product-boundary'], {cwd: root, encoding: 'utf8'});
  if (controller.status !== 0 || !controller.stdout.includes('node-controller residency integration passed')) {
    throw new Error(`controller adapter product-boundary verification failed\n${controller.stdout}\n${controller.stderr}`);
  }
  process.stdout.write(controller.stdout);
}
const selected = [...commandTests, ...warmTests];
const output = run(['test', './internal/nodeagent', '-count=1', '-json', '-run', `^(${selected.join('|')})$`]);
for (const name of selected) {
  if (!output.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"pass"'))) throw new Error(`required test did not produce a passing result: ${name}`);
  if (output.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"skip"'))) throw new Error(`required test was skipped: ${name}`);
}
const schemaOutput = run(['test', './internal/wsproto', '-count=1', '-json', '-run', '^TestResidencyCommandSchemaMatrix$']);
if (!schemaOutput.split('\n').some(line => line.includes('"Test":"TestResidencyCommandSchemaMatrix"') && line.includes('"Action":"pass"')) || schemaOutput.includes('"Action":"skip"')) {
  throw new Error('required shared residency schema matrix did not pass');
}
const controllerOutput = run(['test', './internal/api', '-count=1', '-json', '-run', `^(${controllerTests.join('|')})$`]);
for (const name of controllerTests) {
  if (!controllerOutput.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"pass"'))) throw new Error(`required controller test did not produce a passing result: ${name}`);
  if (controllerOutput.split('\n').some(line => line.includes(`"Test":"${name}"`) && line.includes('"Action":"skip"'))) throw new Error(`required controller test was skipped: ${name}`);
}

if (process.argv.includes('--linux-cross-build')) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'nodeagent-linux-'));
  try {
    const binary = path.join(temp, 'nodeagent.test');
    run(['test', '-c', '-o', binary, './internal/nodeagent'], {...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0'});
    const distro = process.env.NODE_RESIDENCY_WSL_DISTRO || 'Ubuntu';
    const listed = spawnSync('wsl.exe', ['--list', '--quiet'], {encoding: 'utf16le'});
    if (listed.status !== 0 || !listed.stdout.split(/\r?\n/).some(name => name.trim().toLowerCase() === distro.toLowerCase())) {
      throw new Error(`required WSL distribution is unavailable: ${distro}`);
    }
    const toWSLPath = value => {
      const normalized = path.resolve(value).replaceAll('\\', '/');
      const drive = normalized[0].toLowerCase();
      return `/mnt/${drive}${normalized.slice(2)}`;
    };
    const repoWSL = toWSLPath(root);
    const binaryWSL = toWSLPath(binary);
    const linuxNames = ['TestWarmRAMLinuxSyscallIntegration', 'TestWarmRAMLinuxAuthoritativeParsersFailClosed', 'TestWarmRAMLinuxSecureOpenPathReplacementRace'];
    let linuxOutput = '';
    for (const name of linuxNames) {
      const linuxTest = spawnSync('wsl.exe', ['-d', distro, '-u', 'root', '--cd', repoWSL, '--', binaryWSL, `-test.run=^${name}$`, '-test.v'], {encoding: 'utf8'});
      linuxOutput += `${linuxTest.stdout}\n${linuxTest.stderr}`;
      if (linuxTest.status !== 0 || !linuxTest.stdout.includes(name) || linuxTest.stdout.includes('SKIP')) {
        throw new Error(`WSL Linux integration execution failed\n${linuxTest.stdout}\n${linuxTest.stderr}`);
      }
    }
    const unprivilegedTests = spawnSync('wsl.exe', ['-d', distro, '-u', 'berd', '--cd', repoWSL, '--', binaryWSL, '-test.run=^TestWarmRAMLinuxUnprivilegedIntegration$', '-test.v'], {encoding: 'utf8'});
    if (unprivilegedTests.status !== 0 || !unprivilegedTests.stdout.includes('TestWarmRAMLinuxUnprivilegedIntegration') || unprivilegedTests.stdout.includes('SKIP')) {
      throw new Error(`WSL non-root RLIMIT integration execution failed\n${unprivilegedTests.stdout}\n${unprivilegedTests.stderr}`);
    }
    console.log('Linux warm memory contract verification passed');
  } finally {
    fs.rmSync(temp, {recursive: true, force: true});
  }
} else {
  console.log('node residency runtime verification passed');
}
