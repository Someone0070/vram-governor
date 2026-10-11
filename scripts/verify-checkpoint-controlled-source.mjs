import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const mode = args[0] ?? 'default';
if (args.length > 1 || !['default', '--faults', '--regressions'].includes(mode)) {
  console.error('usage: node scripts/verify-checkpoint-controlled-source.mjs [--faults|--regressions]');
  process.exit(2);
}

const controlledTests = [
  'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping',
  'TestCheckpointControlledSourceMappedFootprintUnionAndBounds',
  'TestCheckpointControlledSourceReceiptJSONIsStrict',
  'TestCheckpointControlledSourceLegacyReceiptKeepsPreLeafSignedShape',
  'TestCheckpointControlledSourceUnitJoinKeepsSourceIdentityStable',
];
const custodyTests = [
  'TestCheckpointCustodyRejectsUnboundedAndForgedSourceRequests',
  'TestCheckpointCustodyBeginRequiresExactlyOneModelPlaceholder',
  'TestCheckpointCustodyRejectsDuplicateModelPlaceholder',
  'TestCheckpointCustodyIgnoresArgv0WhenParsingModelOptions',
  'TestCheckpointCustodyQuotaArithmeticRejectsOverflowCases',
  'TestCheckpointCustodyAbortRejectsZeroValueLaunch',
  'TestCheckpointCustodyLinuxRejectsUnknownPID',
  'TestCheckpointCustodyLinuxRejectsUnsupportedFilesystem',
  'TestCheckpointCustodyLinuxVerifyBoundsManyValidReceipts',
  'TestCheckpointCustodyLinuxVerifyRejectsReceiptFIFOWithoutBlocking',
  'TestCheckpointCustodyLinuxArtifactOpenRejectsFIFOWithoutBlocking',
  'TestCheckpointCustodyLinuxPrepareAndStageExecutableRejectFIFOs',
  'TestCheckpointCustodyLinuxStageValidatorsRejectFIFOPathReplacement',
  'TestCheckpointCustodyLinuxVerifyBoundsLiveCandidates',
  'TestCheckpointCustodyStoreMutexHonorsContext',
  'TestCheckpointCustodyLinuxFlockHonorsContext',
  'TestCheckpointCustodyClockAuthorityUsesBootTimeAndBootIDOnly',
  'TestCheckpointCustodyLinuxFSVerityKernelProof',
  'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering',
];
const lifecycleTests = [
  'TestCheckpointCustodyLifecycleRejectsUnsettledRelease',
  'TestCheckpointCustodyLifecycleFailedBeginIsSingleUse',
  'TestCheckpointCustodyLifecycleExactReleaseCycles',
  'TestCheckpointCustodyLifecycleRejectsReplacedModel',
  'TestCheckpointCustodyLifecycleCapturePreservesPreCaptureReplacement',
  'TestCheckpointCustodyLifecycleExecutableAlreadyUnlinked',
  'TestCheckpointCustodyLifecycleAbortRetryRejectsReplacement',
  'TestCheckpointCustodyLifecycleUnknownWaitRetainsPins',
  'TestCheckpointCustodyLifecycleCommitCleanupSettlesBeforeRelease',
];

const custodySource = ['checkpoint_custody_test.go', 'checkpoint_custody_linux_test.go']
  .map((name) => readFileSync(path.join(root, 'internal/nodeagent', name), 'utf8')).join('\n');
const unitSource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_unit_identity_linux_test.go'), 'utf8');
const custodyDeclared = [...custodySource.matchAll(/^func (TestCheckpointControlledSource\w+)\(/gm)].map((match) => match[1]);
const unitDeclared = [...unitSource.matchAll(/^func (TestCheckpointControlledSource\w+)\(/gm)].map((match) => match[1]);
const declared = [...custodyDeclared, ...unitDeclared];
if (declared.length !== controlledTests.length || controlledTests.some((name) => declared.filter((item) => item === name).length !== 1)) {
  throw new Error(`controlled-source feature-test inventory differs: ${declared.join(',')}`);
}

function runNode(script, scriptArgs, timeout = 600_000) {
  const result = spawnSync(process.execPath, [path.join(root, 'scripts', script), ...scriptArgs], {
    cwd: root, encoding: 'utf8', timeout, maxBuffer: 32 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status !== 0) throw new Error(`${script} exited ${result.status ?? 'without a status'}\n${output}`);
  return output;
}

function runControlled(faults) {
  const output = runNode('verify-checkpoint-load-custody.mjs', [
    '--remote-proxmox', '--controlled-source', ...(faults ? ['--faults'] : []),
  ], 1_100_000);
  const marker = faults ? 'checkpoint controlled source fault verification passed' : 'checkpoint controlled source verification passed';
  if (!output.includes(marker)) throw new Error(`controlled-source remote fixture did not emit its exact success marker: ${marker}`);
  return output;
}

if (mode === 'default') {
  runControlled(false);
  console.log('checkpoint controlled source verification passed');
} else if (mode === '--faults') {
  runControlled(true);
  console.log('checkpoint controlled source fault verification passed');
} else {
  const started = Date.now();
  const budgetMs = 1_170_000;
  const runWithinBudget = (script, scriptArgs) => {
    const remaining = budgetMs - (Date.now() - started);
    if (remaining <= 0) throw new Error('controlled-source regression verification exceeded its 1170-second budget');
    const output = runNode(script, scriptArgs, Math.min(remaining, 1_100_000));
    return output;
  };

  // Preserve every old custody selector and its six mutants, then exercise the
  // separate lifecycle, controlled-source, identity, unit, and launcher paths.
  for (const [scriptArgs, token] of [
    [['--remote-proxmox', '--faults'], 'checkpoint load custody fault verification passed'],
    [['--remote-proxmox', '--kernel'], 'checkpoint load custody kernel verification passed'],
    [['--remote-proxmox', '--lifecycle'], 'checkpoint source lifecycle verification passed'],
  ]) {
    const output = runWithinBudget('verify-checkpoint-load-custody.mjs', scriptArgs);
    if (!output.includes(token)) throw new Error(`existing custody selector did not emit ${token}`);
  }
  const controlledFaults = runWithinBudget('verify-checkpoint-load-custody.mjs', ['--remote-proxmox', '--controlled-source', '--faults']);
  if (!controlledFaults.includes('checkpoint controlled source fault verification passed')) throw new Error('controlled-source fault selector did not emit its exact success marker');
  runWithinBudget('verify-checkpoint-local-identity.mjs', []);
  runWithinBudget('verify-checkpoint-unit-identity.mjs', []);
  runWithinBudget('verify-checkpoint-fixed-launcher.mjs', ['--mode=default']);

  const discoveredCustody = [...custodySource.matchAll(/^func (TestCheckpointCustody\w+)\(/gm)].map((match) => match[1]);
  const lifecycleSource = ['checkpoint_custody_lifecycle_test.go', 'checkpoint_custody_lifecycle_linux_test.go']
    .map((name) => readFileSync(path.join(root, 'internal/nodeagent', name), 'utf8')).join('\n');
  const discoveredLifecycle = [...lifecycleSource.matchAll(/^func (TestCheckpointCustodyLifecycle\w+)\(/gm)].map((match) => match[1]);
  if (discoveredCustody.length !== custodyTests.length || custodyTests.some((name) => discoveredCustody.filter((item) => item === name).length !== 1)) throw new Error('old nineteen-test custody inventory changed');
  if (discoveredLifecycle.length !== lifecycleTests.length || lifecycleTests.some((name) => discoveredLifecycle.filter((item) => item === name).length !== 1)) throw new Error('old nine-test lifecycle inventory changed');
  console.log('checkpoint controlled source regression verification passed');
}
