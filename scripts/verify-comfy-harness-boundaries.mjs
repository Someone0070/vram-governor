import { existsSync, mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { tmpdir } from 'node:os';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = path.join(root, 'internal', 'comfyharness', 'server_test.go');
const source = readFileSync(sourcePath, 'utf8');

// This inventory is intentionally explicit. Keep descriptions beside each
// runnable case so additions to a suite state which behavior they observe.
const cases = {
  TestManagedComfySafeBoundaryAndResume: 'durable checkpoint, resume, output and completion path',
  TestManagedComfyYieldAndResume: 'yield boundary and idempotent resume path',
  TestManagedComfyCancelConfirmsBackendStop: 'exact queued prompt deletion positive control',
  TestManagedComfyCancelDoesNotInterruptExactRunningPrompt: 'running prompt and native workflow protection plus late completion fencing',
  TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody: 'cancel during an accepted but unjournaled POST remains uncertain',
  TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey: 'same key with different actual prompt payload is rejected',
  TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated: 'chunk storage fault and restart dedupe',
  TestManagedComfyLostPromptResponseIsNeverResubmitted: 'response-lost accepted POST is not retried',
  TestManagedComfyAcceptedThenServerErrorIsNeverResubmitted: 'accepted prompt followed by HTTP 500 remains ambiguous',
  TestManagedComfySubmissionIntentFaultPreventsPromptPost: 'submission-intent storage failure prevents POST',
  TestManagedComfyCheckpointCommitFailureStaysUncertain: 'checkpoint ACK storage fault and restart recovery',
  TestManagedComfyResumePersistFailureRollsBackMemory: 'resume storage fault rolls memory back to durable checkpoint',
  TestManagedComfyCancelCommitFailureIsNotAcknowledged: 'cancel ACK storage fault',
  TestManagedComfyStopTimeoutStaysUncertain: 'exact queued stop timeout remains uncertain',
  TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel: 'invalid exact queue/history observation cannot confirm stop',
  TestManagedComfyRejectsCorruptDurableSnapshot: 'corrupt persisted payload identity is rejected',
  TestManagedComfyRejectsConcurrentStateOwner: 'second process cannot overwrite an active state directory',
  TestManagedComfyStateOwnerLockReleasesAfterAbruptExit: 'OS releases active state-directory ownership after abrupt process exit',
  TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot: 'configured write/recovery byte budget preserves last durable state across overflow and restart',
  TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates: 'near-quota acknowledged state has recovery headroom and same-key restart deduplicates',
  TestManagedComfyRestartRecoveryHeadroomRequired: 'current snapshot is rejected before write when restart reconciliation would exceed the same byte limit',
  TestManagedComfyCheckpointReferenceIsFreshPerEpoch: 'old resume ref cannot cross a newer boundary at unchanged progress or survive consumption',
  TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference: 'durable legacy checkpoint lacking valid epoch-bound reference is rejected',
  TestManagedComfyRestartFailsUnconfirmedRun: 'restart preserves unresolved prompt custody',
  TestComfyVerifierNegativeControl: 'opt-in intentionally failing assertion used to validate verifier sensitivity',
};

const suites = {
  default: [
    'TestManagedComfySafeBoundaryAndResume',
    'TestManagedComfyCancelConfirmsBackendStop',
    'TestManagedComfyCancelDoesNotInterruptExactRunningPrompt',
    'TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody',
    'TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel',
    'TestManagedComfyCheckpointReferenceIsFreshPerEpoch',
    'TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot',
    'TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates',
    'TestManagedComfyRestartRecoveryHeadroomRequired',
    'TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference',
  ],
  '--durability': [
    'TestManagedComfySafeBoundaryAndResume',
    'TestManagedComfyYieldAndResume',
    'TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey',
    'TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated',
    'TestManagedComfyCheckpointCommitFailureStaysUncertain',
    'TestManagedComfyResumePersistFailureRollsBackMemory',
    'TestManagedComfyCancelCommitFailureIsNotAcknowledged',
    'TestManagedComfySubmissionIntentFaultPreventsPromptPost',
    'TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot',
    'TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates',
    'TestManagedComfyRestartRecoveryHeadroomRequired',
    'TestManagedComfyCheckpointReferenceIsFreshPerEpoch',
    'TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference',
  ],
  '--faults': [
    'TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody',
    'TestManagedComfyLostPromptResponseIsNeverResubmitted',
    'TestManagedComfyAcceptedThenServerErrorIsNeverResubmitted',
    'TestManagedComfySubmissionIntentFaultPreventsPromptPost',
    'TestManagedComfyCancelDoesNotInterruptExactRunningPrompt',
    'TestManagedComfyRestartFailsUnconfirmedRun',
    'TestManagedComfyCheckpointReferenceIsFreshPerEpoch',
    'TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference',
    'TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated',
    'TestManagedComfyCheckpointCommitFailureStaysUncertain',
    'TestManagedComfyResumePersistFailureRollsBackMemory',
    'TestManagedComfyCancelCommitFailureIsNotAcknowledged',
    'TestManagedComfyStopTimeoutStaysUncertain',
    'TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey',
    'TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel',
    'TestManagedComfyRejectsCorruptDurableSnapshot',
    'TestManagedComfyRejectsConcurrentStateOwner',
    'TestManagedComfyStateOwnerLockReleasesAfterAbruptExit',
    'TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot',
    'TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates',
    'TestManagedComfyRestartRecoveryHeadroomRequired',
  ],
};

// Linux's filesystem permission and directory-sync semantics are part of this
// boundary. Keep this inventory exact so the Linux fault pass proves every
// managed harness test ran without a skip, not merely that the binary exited.
const linuxInventory = [
  'TestManagedComfySafeBoundaryAndResume',
  'TestManagedComfyYieldAndResume',
  'TestManagedComfyCancelConfirmsBackendStop',
  'TestManagedComfyCancelDoesNotInterruptExactRunningPrompt',
  'TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody',
  'TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey',
  'TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated',
  'TestManagedComfyLostPromptResponseIsNeverResubmitted',
  'TestManagedComfyAcceptedThenServerErrorIsNeverResubmitted',
  'TestManagedComfySubmissionIntentFaultPreventsPromptPost',
  'TestManagedComfyCheckpointCommitFailureStaysUncertain',
  'TestManagedComfyResumePersistFailureRollsBackMemory',
  'TestManagedComfyCancelCommitFailureIsNotAcknowledged',
  'TestManagedComfyStopTimeoutStaysUncertain',
  'TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel',
  'TestManagedComfyRejectsCorruptDurableSnapshot',
  'TestManagedComfyRejectsConcurrentStateOwner',
  'TestManagedComfyStateOwnerLockReleasesAfterAbruptExit',
  'TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot',
  'TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates',
  'TestManagedComfyRestartRecoveryHeadroomRequired',
  'TestManagedComfyCheckpointReferenceIsFreshPerEpoch',
  'TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference',
  'TestManagedComfyRestartFailsUnconfirmedRun',
  'TestManagedComfyRequiresAuthorization',
];

if (process.argv.length > 3 || (process.argv.length === 3 && !(process.argv[2] in suites))) {
  process.stderr.write('usage: node scripts/verify-comfy-harness-boundaries.mjs [--durability|--faults]\n');
  process.exit(2);
}

const selected = suites[process.argv[2] ?? 'default'];
for (const [name, description] of Object.entries(cases)) {
  const matches = source.match(new RegExp(`^func ${name}\\(`, 'gm')) ?? [];
  if (matches.length !== 1) {
    process.stderr.write(`declared test inventory is invalid: ${name} (${description}), definitions=${matches.length}\n`);
    process.exit(1);
  }
}
if (new Set(linuxInventory).size !== linuxInventory.length) {
  process.stderr.write('Linux test inventory contains duplicate names\n');
  process.exit(1);
}
for (const name of linuxInventory) {
  const matches = source.match(new RegExp(`^func ${name}\\(`, 'gm')) ?? [];
  if (matches.length !== 1) {
    process.stderr.write(`Linux test inventory is invalid: ${name}, definitions=${matches.length}\n`);
    process.exit(1);
  }
}
for (const name of selected) {
  if (!(name in cases)) {
    process.stderr.write(`suite references a case absent from the declared inventory: ${name}\n`);
    process.exit(1);
  }
}
if (new Set(selected).size !== selected.length) {
  process.stderr.write('selected test suite contains duplicate cases\n');
  process.exit(1);
}

function parseEvents(output) {
  const events = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line.startsWith('{')) continue;
    try { events.push(JSON.parse(line)); } catch { /* non-event compiler lines are checked by process status */ }
  }
  return events;
}

function runGo(args, extraEnv = {}) {
  return spawnSync('go', args, {
    cwd: root,
    encoding: 'utf8',
    windowsHide: true,
    timeout: 45000,
    maxBuffer: 2 * 1024 * 1024,
    env: { ...process.env, ...extraEnv },
  });
}

function verifyRecoveryHeadroomMutation() {
  const temporaryDirectory = mkdtempSync(path.join(tmpdir(), 'comfy-harness-recovery-mutant-'));
  const mutantPath = path.join(temporaryDirectory, 'server-mutant.go');
  const overlayPath = path.join(temporaryDirectory, 'overlay.json');
  try {
    const serverPath = path.join(root, 'internal', 'comfyharness', 'server.go');
    const original = readFileSync(serverPath, 'utf8');
    const guard = '\tif int64(len(recoveryBody)+1) > s.options.MaxStateBytes {';
    if (original.split(guard).length !== 2) {
      process.stderr.write('recovery-headroom mutation target is absent or ambiguous\n');
      return false;
    }
    // Keep recoveryBody referenced so this is a compiling guard-removal
    // mutant, not a compiler-error negative control.
    const weakened = original.replace(guard, '\tif int64(len(recoveryBody)+1) < 0 {');
    writeFileSync(mutantPath, weakened, { flag: 'wx' });
    writeFileSync(overlayPath, JSON.stringify({ Replace: { [serverPath]: mutantPath } }), { flag: 'wx' });
    const result = runGo(['test', '-json', '-overlay', overlayPath, './internal/comfyharness', '-run', '^TestManagedComfyRestartRecoveryHeadroomRequired$', '-count=1', '-timeout=10s']);
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    const events = parseEvents(result.stdout ?? '');
    const namedFailure = events.some((event) => event.Test === 'TestManagedComfyRestartRecoveryHeadroomRequired' && event.Action === 'fail');
    if (result.error || result.status === 0 || result.signal || !namedFailure || !output.includes('RESTART_RECOVERY_HEADROOM_ASSERTION') || output.includes('[build failed]')) {
      process.stderr.write('recovery-headroom mutant was not rejected by the named behavioral assertion\n');
      if (output) process.stderr.write(output);
      return false;
    }
    process.stdout.write('compiling recovery-headroom guard-removal mutant failed the named behavioral assertion as expected\n');
    return true;
  } finally {
    if (existsSync(mutantPath)) unlinkSync(mutantPath);
    if (existsSync(overlayPath)) unlinkSync(overlayPath);
    rmdirSync(temporaryDirectory);
  }
}

function verifyStaleResumeMutation() {
  const temporaryDirectory = mkdtempSync(path.join(tmpdir(), 'comfy-harness-resume-mutant-'));
  const mutantPath = path.join(temporaryDirectory, 'server-mutant.go');
  const overlayPath = path.join(temporaryDirectory, 'overlay.json');
  try {
    const serverPath = path.join(root, 'internal', 'comfyharness', 'server.go');
    const original = readFileSync(serverPath, 'utf8');
    const guard = '\t\t\tif request.CheckpointRef == "" || request.CheckpointRef != existing.CheckpointRef {';
    if (original.split(guard).length !== 2) {
      process.stderr.write('stale-resume mutation target is absent or ambiguous\n');
      return false;
    }
    const weakened = original.replace(guard, '\t\t\tif false {');
    writeFileSync(mutantPath, weakened, { flag: 'wx' });
    writeFileSync(overlayPath, JSON.stringify({ Replace: { [serverPath]: mutantPath } }), { flag: 'wx' });
    const result = runGo(['test', '-json', '-overlay', overlayPath, './internal/comfyharness', '-run', '^TestManagedComfySafeBoundaryAndResume$', '-count=1', '-timeout=10s']);
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    const events = parseEvents(result.stdout ?? '');
    const namedFailure = events.some((event) => event.Test === 'TestManagedComfySafeBoundaryAndResume' && event.Action === 'fail');
    if (result.error || result.status === 0 || result.signal || !namedFailure || !output.includes('STALE_START_RETRY_ASSERTION') || output.includes('[build failed]')) {
      process.stderr.write('stale-resume mutant was not rejected by the named behavioral assertion\n');
      if (output) process.stderr.write(output);
      return false;
    }
    process.stdout.write('compiling stale-resume guard-removal mutant failed the named behavioral assertion as expected\n');
    return true;
  } finally {
    if (existsSync(mutantPath)) unlinkSync(mutantPath);
    if (existsSync(overlayPath)) unlinkSync(overlayPath);
    rmdirSync(temporaryDirectory);
  }
}

function verifyLinuxBehavior() {
  let result;
  if (process.platform === 'linux') {
    if (typeof process.getuid === 'function' && process.getuid() === 0) {
      process.stderr.write('Linux fault verification must run as a non-root user\n');
      return false;
    }
    const pattern = `^(${linuxInventory.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})$`;
    result = spawnSync('go', ['test', '-v', './internal/comfyharness', '-run', pattern, '-count=1', '-timeout=45s'], {
      cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 4 * 1024 * 1024,
      env: { ...process.env, TMPDIR: '/tmp' },
    });
  } else if (process.platform === 'win32') {
    const binaryDirectory = mkdtempSync(path.join(tmpdir(), 'comfy-harness-linux-'));
    const binary = path.join(binaryDirectory, 'harness.test');
    try {
      const compilation = spawnSync('go', ['test', '-c', '-o', binary, './internal/comfyharness'], {
        cwd: root, encoding: 'utf8', timeout: 60000, maxBuffer: 2 * 1024 * 1024,
        env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
      });
      if (compilation.error || compilation.status !== 0 || !existsSync(binary)) {
        process.stderr.write('could not cross-compile Linux harness verification binary\n');
        if (compilation.stdout) process.stderr.write(compilation.stdout);
        if (compilation.stderr) process.stderr.write(compilation.stderr);
        return false;
      }
      const wslPath = spawnSync('wsl.exe', ['-d', 'Ubuntu', '-e', 'wslpath', '-a', binary], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024,
      });
      const linuxBinary = (wslPath.stdout ?? '').replaceAll('\0', '').trim();
      if (wslPath.error || wslPath.status !== 0 || !linuxBinary) {
        process.stderr.write('Ubuntu WSL is required for Linux harness verification\n');
        if (wslPath.stderr) process.stderr.write(wslPath.stderr);
        return false;
      }
      const uid = spawnSync('wsl.exe', ['-d', 'Ubuntu', '-u', 'nobody', '--exec', 'id', '-u'], {
        encoding: 'utf8', timeout: 15000, maxBuffer: 1024 * 1024,
      });
      if (uid.error || uid.status !== 0 || (uid.stdout ?? '').replaceAll('\0', '').trim() !== '65534') {
        process.stderr.write('Ubuntu WSL could not provide the non-root nobody user\n');
        return false;
      }
      result = spawnSync('wsl.exe', [
        '-d', 'Ubuntu', '-u', 'nobody', '--exec', 'env', 'TMPDIR=/tmp', linuxBinary,
        '-test.run=^TestManagedComfy', '-test.count=1', '-test.timeout=45s', '-test.v',
      ], { encoding: 'utf8', timeout: 75000, maxBuffer: 4 * 1024 * 1024 });
    } finally {
      if (existsSync(binary)) unlinkSync(binary);
      rmdirSync(binaryDirectory);
    }
  } else {
    process.stderr.write(`Linux fault verification unsupported on ${process.platform}\n`);
    return false;
  }

  if (result.error || result.status !== 0 || result.signal) {
    process.stderr.write('Linux managed harness test process failed\n');
    if (result.error) process.stderr.write(`${result.error.message}\n`);
    if (result.stdout) process.stderr.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    return false;
  }
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const passed = new Set([...output.matchAll(/^--- PASS: (TestManagedComfy\w+) \(/gm)].map((match) => match[1]));
  const missing = linuxInventory.filter((name) => !passed.has(name));
  const skipped = output.match(/^--- SKIP: /gm) ?? [];
  const failed = output.match(/^--- FAIL: /gm) ?? [];
  if (missing.length || skipped.length || failed.length) {
    process.stderr.write(`Linux test inventory mismatch; missing=${missing.join(', ') || 'none'}, skips=${skipped.length}, failures=${failed.length}\n`);
    process.stderr.write(output);
    return false;
  }
  process.stdout.write(output);
  process.stdout.write(`Linux managed harness verification passed (${passed.size} exact cases, no skips)\n`);
  return passed.size === linuxInventory.length;
}

// A deliberately failing test proves this verifier cannot accept a green
// process that did not actually pass its named cases.
const negative = runGo(['test', '-json', './internal/comfyharness', '-run', '^TestComfyVerifierNegativeControl$', '-count=1', '-timeout=10s'], {
  COMFY_HARNESS_NEGATIVE_CONTROL: '1',
});
if (negative.error || negative.status === 0 || negative.signal) {
  process.stderr.write('negative control did not fail as designed\n');
  if (negative.error) process.stderr.write(`${negative.error.message}\n`);
  process.exit(1);
}
const negativeEvents = parseEvents(negative.stdout ?? '');
const negativeFailure = negativeEvents.some((event) => event.Test === 'TestComfyVerifierNegativeControl' && event.Action === 'fail');
if (!negativeFailure || !`${negative.stdout ?? ''}${negative.stderr ?? ''}`.includes('COMFY_HARNESS_NEGATIVE_CONTROL_ASSERTION')) {
  process.stderr.write('negative control did not reach its named failing assertion\n');
  process.exit(1);
}

const escaped = selected.map((name) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
const pattern = `^(${escaped.join('|')})$`;
const result = runGo(['test', '-json', './internal/comfyharness', '-run', pattern, '-count=1', '-timeout=30s']);
if (result.error) {
  process.stderr.write(`could not run the declared Go test inventory: ${result.error.message}\n`);
  process.exit(1);
}
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);
const events = parseEvents(result.stdout ?? '');
const outcomes = new Map();
for (const event of events) {
  if (!event.Test || !selected.includes(event.Test)) continue;
  if (event.Action === 'pass' || event.Action === 'fail' || event.Action === 'skip') outcomes.set(event.Test, event.Action);
}
const invalid = selected.filter((name) => outcomes.get(name) !== 'pass');
if (result.signal || result.status !== 0 || invalid.length > 0) {
  process.stderr.write(`Comfy harness cases did not all pass: ${invalid.join(', ') || '(package command failed)'}; exit=${result.status}, signal=${result.signal ?? 'none'}\n`);
  process.exit(result.status || 1);
}

if ((process.argv[2] ?? 'default') === '--faults') {
  if (!verifyRecoveryHeadroomMutation() || !verifyStaleResumeMutation() || !verifyLinuxBehavior()) process.exit(1);
}

const labels = {
  default: 'managed Comfy harness boundary verification passed',
  '--durability': 'managed Comfy harness durability verification passed',
  '--faults': 'managed Comfy harness fault verification passed',
};
process.stdout.write(`${labels[process.argv[2] ?? 'default']}\n`);
