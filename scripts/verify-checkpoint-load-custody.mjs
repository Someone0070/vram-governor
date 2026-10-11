import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, rmdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv.slice(2);
const allowedModes = new Set(['--remote-proxmox', '--kernel', '--faults', '--transport-self-test', '--lifecycle', '--controlled-source', '--reuse', '--owned-stop']);
const controlledSourceMode = mode.includes('--controlled-source');
const reuseMode = mode.includes('--reuse');
const ownedStopMode = mode.includes('--owned-stop');
const ownedStopModeInvalid = ownedStopMode && (
  !mode.includes('--remote-proxmox') ||
  mode.some((arg) => !['--remote-proxmox', '--owned-stop', '--faults'].includes(arg)) ||
  reuseMode || controlledSourceMode || mode.includes('--lifecycle') || mode.includes('--kernel') || mode.includes('--transport-self-test')
);
if (mode.some((arg) => !allowedModes.has(arg)) || new Set(mode).size !== mode.length || (mode.includes('--kernel') && mode.includes('--faults')) || (mode.includes('--lifecycle') && (mode.includes('--kernel') || mode.includes('--transport-self-test'))) || (mode.includes('--transport-self-test') && mode.length !== 1) || (controlledSourceMode && (!mode.includes('--remote-proxmox') || mode.some((arg) => !['--remote-proxmox', '--controlled-source', '--faults'].includes(arg)))) || (reuseMode && (!mode.includes('--remote-proxmox') || mode.some((arg) => !['--reuse', '--remote-proxmox', '--faults'].includes(arg)))) || ownedStopModeInvalid) {
  console.error('usage: node scripts/verify-checkpoint-load-custody.mjs [--remote-proxmox] [--kernel|--faults|--lifecycle] | --controlled-source --remote-proxmox [--faults] | --reuse --remote-proxmox [--faults] | --owned-stop --remote-proxmox [--faults] | --transport-self-test');
  process.exit(2);
}
const allTests = [
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
const controlledSourceTests = [
  'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping',
  'TestCheckpointControlledSourceMappedFootprintUnionAndBounds',
  'TestCheckpointControlledSourceReceiptJSONIsStrict',
  'TestCheckpointControlledSourceLegacyReceiptKeepsPreLeafSignedShape',
  'TestCheckpointControlledSourceUnitJoinKeepsSourceIdentityStable',
];
const reuseTests = [
  'TestCheckpointCustodyReuseFreshProcessesNoCopy',
  'TestCheckpointCustodyReuseRejectsOrphansAndTampering',
  'TestCheckpointCustodyReuseConcurrentPreparationCopiesOnce',
  'TestCheckpointCustodyReuseRejectsUnboundedAndForgedSourceRequests',
];
const ownedStopTests = ['TestCheckpointFixedOwnedStopRemoteKernelFixture'];
const ownedStopTestSource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_fixed_launcher_linux_test.go'), 'utf8');
const ownedStopDeclared = [...ownedStopTestSource.matchAll(/^func (TestCheckpointFixedOwnedStop\w+)\(/gm)].map((m) => m[1]);
if (ownedStopDeclared.filter((name) => name === ownedStopTests[0]).length !== 1) {
  throw new Error(`owned-stop kernel test inventory mismatch: declared=${ownedStopDeclared.join(',')}`);
}
const reuseTestFiles = ['checkpoint_custody_reuse_test.go', 'checkpoint_custody_reuse_linux_test.go'];
const reuseTestSource = reuseTestFiles.map((f) => readFileSync(path.join(root, 'internal/nodeagent', f), 'utf8')).join('\n');
const reuseDeclared = [...reuseTestSource.matchAll(/^func (TestCheckpointCustodyReuse\w+)\(/gm)].map((m) => m[1]);
const reuseDeclaredExpected = [...reuseTests];
if (reuseDeclared.length !== reuseDeclaredExpected.length || reuseDeclaredExpected.some((name) => reuseDeclared.filter((found) => found === name).length !== 1) || reuseDeclared.some((name) => !reuseDeclaredExpected.includes(name))) {
  throw new Error(`reuse test inventory mismatch: declared=${reuseDeclared.join(',')}`);
}
const files = ['checkpoint_custody_test.go', 'checkpoint_custody_linux_test.go'];
const source = files.map((f) => readFileSync(path.join(root, 'internal/nodeagent', f), 'utf8')).join('\n');
const controlledSourceTestFiles = ['checkpoint_custody_linux_test.go', 'checkpoint_unit_identity_linux_test.go'];
const controlledSourceTestSource = controlledSourceTestFiles.map((f) => readFileSync(path.join(root, 'internal/nodeagent', f), 'utf8')).join('\n');
const controlledDeclared = [...controlledSourceTestSource.matchAll(/^func (TestCheckpointControlledSource\w+)\(/gm)].map((m) => m[1]);
if (controlledDeclared.length !== controlledSourceTests.length || controlledSourceTests.some((name) => controlledDeclared.filter((found) => found === name).length !== 1)) {
  throw new Error(`controlled-source test inventory mismatch: declared=${controlledDeclared.join(',')}`);
}
const linuxCustodySource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_custody_linux.go'), 'utf8');
const genericCustodySource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_custody.go'), 'utf8');
const clockSources = `${genericCustodySource}\n${linuxCustodySource}`;
if (!/unix\.Fstatfs\(fd,\s*&fs\)/.test(linuxCustodySource) ||
    !/blockSize\s*:=\s*uint64\(os\.Getpagesize\(\)\)/.test(linuxCustodySource) ||
    !/\*\(\*uint32\)\(unsafe\.Pointer\(&arg\[8\]\)\)\s*=\s*uint32\(blockSize\)/.test(linuxCustodySource) ||
    !/\*\(\*uint32\)\(unsafe\.Pointer\(&arg\[8\]\)\); uint64\(got\) != blockSize/.test(source)) {
  throw new Error('fs-verity source oracle failed: enable argument must carry a supported nonzero filesystem/page block size at offset 8');
}
if (!/unix\.ClockGettime\(checkpointCustodyClockID\(\),\s*&ts\)/.test(linuxCustodySource) ||
    !/func checkpointCustodyClockID\(\) int32\s+\{\s*return unix\.CLOCK_BOOTTIME\s*\}/.test(linuxCustodySource) ||
    !/func checkpointCustodyBootIDPath\(\) string\s+\{\s*return "\/proc\/sys\/kernel\/random\/boot_id"\s*\}/.test(linuxCustodySource) ||
    !/PrelaunchBootNS:\s*l\.preBootNS/.test(linuxCustodySource) ||
    !/StartBootNS:\s*l\.startBootNS/.test(linuxCustodySource) ||
    !/StartedBootNS:\s*l\.startedBootNS/.test(linuxCustodySource) ||
    !/BootID:\s*l\.bootID/.test(linuxCustodySource)) {
  throw new Error('custody clock source oracle failed: receipt launch authority must bind CLOCK_BOOTTIME and kernel boot ID');
}
for (const forbidden of [/time\.Now\s*\(/i, /\.ModTime\s*\(/i, /\bctime\b/i, /\bmtime\b/i, /\bbtime\b/i, /CLOCK_REALTIME/i]) {
  if (forbidden.test(clockSources)) throw new Error(`custody clock source oracle failed: forbidden wall/file timestamp authority (${forbidden})`);
}
const declared = [...source.matchAll(/^func (TestCheckpointCustody\w+)\(/gm)].map((m) => m[1]);
if (declared.length !== allTests.length || allTests.some((n) => !declared.includes(n))) {
  throw new Error(`custody test inventory mismatch: declared=${declared.join(',')}`);
}
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
const lifecycleFiles = ['checkpoint_custody_lifecycle_test.go', 'checkpoint_custody_lifecycle_linux_test.go'];
const lifecycleSource = lifecycleFiles.map((f) => readFileSync(path.join(root, 'internal/nodeagent', f), 'utf8')).join('\n');
const lifecycleDeclared = [...lifecycleSource.matchAll(/^func (TestCheckpointCustodyLifecycle\w+)\(/gm)].map((m) => m[1]);
if (lifecycleDeclared.length !== lifecycleTests.length || lifecycleTests.some((n) => !lifecycleDeclared.includes(n))) {
  throw new Error(`source lifecycle test inventory mismatch: declared=${lifecycleDeclared.join(',')}`);
}

function selectCustodyTests(args) {
  if (args.includes('--owned-stop')) return ownedStopTests;
  if (args.includes('--reuse')) return reuseTests;
  if (args.includes('--controlled-source')) return controlledSourceTests;
  if (args.includes('--lifecycle')) return lifecycleTests;
  if (args.includes('--kernel')) return ['TestCheckpointCustodyLinuxFSVerityKernelProof', 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering'];
  return allTests;
}

function assertCustodySelector(label, args, expected) {
  const selected = selectCustodyTests(args);
  if (JSON.stringify(selected) !== JSON.stringify(expected)) throw new Error(`custody selector regression for ${label}: selected=${selected}`);
}

function selfTestCustodySelectors() {
  assertCustodySelector('default', [], allTests);
  assertCustodySelector('kernel', ['--kernel'], ['TestCheckpointCustodyLinuxFSVerityKernelProof', 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering']);
  assertCustodySelector('lifecycle', ['--lifecycle'], lifecycleTests);
  assertCustodySelector('controlled-source', ['--controlled-source'], controlledSourceTests);
  assertCustodySelector('reuse', ['--reuse'], reuseTests);
  assertCustodySelector('owned-stop', ['--owned-stop'], ownedStopTests);
}
selfTestCustodySelectors();

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 240_000, maxBuffer: 4 * 1024 * 1024, ...options });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status !== 0) { process.stderr.write(output); throw new Error(`${program} exited ${result.status ?? 'without a status'}`); }
  return output;
}

function assertTests(output, expected) {
  const passed = new Set(); const skipped = new Set(); const failed = new Set();
  for (const line of output.split(/\r?\n/)) {
    const pass = line.match(/^--- PASS: (\S+)/); const skip = line.match(/^--- SKIP: (\S+)/); const fail = line.match(/^--- FAIL: (\S+)/);
    if (pass) passed.add(pass[1]); if (skip) skipped.add(skip[1]); if (fail) failed.add(fail[1]);
  }
  const missing = expected.filter((n) => !passed.has(n));
  const unexpected = [...passed].filter((n) => !expected.includes(n));
  if (missing.length || unexpected.length || skipped.size || failed.size) {
    throw new Error(`test evidence mismatch; missing=${missing}; skipped=${[...skipped]}; failed=${[...failed]}; unexpected=${unexpected}`);
  }
}

function controlledSourceInventoryErrors(output, expected) {
  const runs = [], passes = [], skips = [], failures = [];
  const malformed = [];
  for (const line of output.split(/\r?\n/)) {
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const match = line.match(/^=== RUN\s+(\S+)$/);
      if (match) runs.push(match[1]); else malformed.push(line);
      continue;
    }
    const terminalMatch = line.match(/^\s*--- (PASS|SKIP|FAIL):/);
    if (!terminalMatch) continue;
    const match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)$/);
    if (!match) {
      malformed.push(line);
      continue;
    }
    if (match[1] === 'PASS') passes.push(match[2]);
    else if (match[1] === 'SKIP') skips.push(match[2]);
    else failures.push(match[2]);
  }
  const counts = (values) => values.reduce((map, value) => map.set(value, (map.get(value) ?? 0) + 1), new Map());
  const runCounts = counts(runs), passCounts = counts(passes);
  const missingRuns = expected.filter((name) => runCounts.get(name) !== 1);
  const missingPasses = expected.filter((name) => passCounts.get(name) !== 1);
  const unexpectedRuns = runs.filter((name) => !expected.includes(name));
  const unexpectedPasses = passes.filter((name) => !expected.includes(name));
  return { missingRuns, missingPasses, skips, failures, unexpectedRuns, unexpectedPasses, malformed };
}

function assertControlledSourceRunInventory(output) {
  const top = [
    'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping',
    'TestCheckpointControlledSourceMappedFootprintUnionAndBounds',
    'TestCheckpointControlledSourceReceiptJSONIsStrict',
    'TestCheckpointControlledSourceLegacyReceiptKeepsPreLeafSignedShape',
    'TestCheckpointControlledSourceUnitJoinKeepsSourceIdentityStable',
  ];
  const subtests = [
    ...['unmapped', 'partial', 'fifo', 'closed-fd', 'swapped-fd', 'wrong-argv', 'listener-drift', 'public-v1', 'terminal-release', 'terminal-tampered-executable'].map((name) => `TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping/${name}`),
    'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping/unmapped/authenticated-unit-join',
    'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping/unmapped/changed-second-unit-sample',
    ...['source-inode', 'source-verity', 'executable-inode', 'executable-verity', 'argv', 'start-ticks', 'listener', 'unknown-pid'].map((name) => `TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping/unmapped/receipt-${name}`),
    ...['unknown', 'duplicate', 'case-variant', 'null', 'missing-executable', 'null-executable', 'trailing', 'downgraded'].map((name) => `TestCheckpointControlledSourceReceiptJSONIsStrict/${name}`),
  ];
  const expected = [...top, ...subtests];
  const errors = controlledSourceInventoryErrors(output, expected);
  if (errors.missingRuns.length || errors.missingPasses.length || errors.skips.length || errors.failures.length || errors.unexpectedRuns.length || errors.unexpectedPasses.length || errors.malformed.length) {
    throw new Error(`controlled-source test occurrence mismatch; run=${errors.missingRuns}; pass=${errors.missingPasses}; skip=${errors.skips}; failed=${errors.failures}; unexpected-run=${errors.unexpectedRuns}; unexpected-pass=${errors.unexpectedPasses}; malformed=${errors.malformed}`);
  }
}

function selfTestControlledSourceRunInventory() {
  const expected = ['TestControlledParser', 'TestControlledParser/nested'];
  const good = [
    '=== RUN   TestControlledParser',
    '=== RUN   TestControlledParser/nested',
    '    --- PASS: TestControlledParser/nested (0.00s)',
    '--- PASS: TestControlledParser (0.00s)',
  ].join('\n');
  const cases = [
    { name: 'positive-indented-subtest', output: good, shouldPass: true },
    { name: 'missing', output: good.replace('    --- PASS: TestControlledParser/nested (0.00s)\n', ''), shouldPass: false },
    { name: 'duplicate', output: `${good}\n    --- PASS: TestControlledParser/nested (0.00s)`, shouldPass: false },
    { name: 'skipped', output: good.replace('    --- PASS: TestControlledParser/nested', '    --- SKIP: TestControlledParser/nested'), shouldPass: false },
    { name: 'unexpected-controlled', output: `${good}\n=== RUN   TestControlledParser/unexpected\n    --- PASS: TestControlledParser/unexpected (0.00s)`, shouldPass: false },
    { name: 'unexpected-noncontrolled', output: `${good}\n=== RUN   TestBogus\n--- PASS: TestBogus (0.00s)`, shouldPass: false },
    { name: 'empty-run-name', output: `${good}\n=== RUN   `, shouldPass: false },
    { name: 'trailing-run-text', output: `${good}\n=== RUN   TestBogus trailing`, shouldPass: false },
    { name: 'invalid-pass-duration', output: `${good}\n--- PASS: TestBogus (unknown)`, shouldPass: false },
  ];
  for (const test of cases) {
    const errors = controlledSourceInventoryErrors(test.output, expected);
    const failed = errors.missingRuns.length || errors.missingPasses.length || errors.skips.length || errors.failures.length || errors.unexpectedRuns.length || errors.unexpectedPasses.length || errors.malformed.length;
    if (Boolean(failed) === test.shouldPass) throw new Error(`controlled-source inventory parser self-test failed: ${test.name}`);
  }
}

selfTestControlledSourceRunInventory();

function reuseInventoryErrors(output, expected) {
  const runs = [], passes = [], skips = [], failures = [], malformed = [];
  for (const line of output.split(/\r?\n/)) {
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const match = line.match(/^=== RUN\s+(\S+)$/);
      if (match) runs.push(match[1]); else malformed.push(line);
      continue;
    }
    const terminal = line.match(/^\s*--- (PASS|SKIP|FAIL):/);
    if (!terminal) continue;
    const match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)$/);
    if (!match) { malformed.push(line); continue; }
    if (match[1] === 'PASS') passes.push(match[2]);
    else if (match[1] === 'SKIP') skips.push(match[2]);
    else failures.push(match[2]);
  }
  const counts = (values) => values.reduce((map, value) => map.set(value, (map.get(value) ?? 0) + 1), new Map());
  const runCounts = counts(runs), passCounts = counts(passes);
  return {
    missingRuns: expected.filter((name) => runCounts.get(name) !== 1),
    missingPasses: expected.filter((name) => passCounts.get(name) !== 1),
    unexpectedRuns: runs.filter((name) => !expected.includes(name)),
    unexpectedPasses: passes.filter((name) => !expected.includes(name)),
    skips, failures, malformed,
  };
}

function assertReuseRunInventory(output) {
  const nested = ['missing-record-existing-stage', 'wrong-source-key', 'bad-signature', 'replaced-inode', 'partial-stage', 'verity-substitution', 'symlink', 'fifo', 'hardlink', 'metadata-symlink', 'metadata-fifo', 'metadata-hardlink', 'canonical-duplicate', 'canonical-case', 'canonical-trailing', 'canonical-null', 'wrong-approved-hash', 'source-content-changed', 'model-temp-sync-failure', 'record-temp-sync-failure', 'model-temp-replacement', 'record-temp-replacement', 'model-temp-successful-substitution', 'record-temp-successful-substitution', 'reserve-quota', 'unknown-orphan-charged', 'stale-handle', 'failed-begin-retains-cache', 'failed-begin-after-executable-stage', 'failed-commit-retains-charge', 'unknown-reap-retains-charge'];
  const expected = [...reuseTests, ...nested.map((name) => `TestCheckpointCustodyReuseRejectsOrphansAndTampering/${name}`)];
  const errors = reuseInventoryErrors(output, expected);
  if (errors.missingRuns.length || errors.missingPasses.length || errors.unexpectedRuns.length || errors.unexpectedPasses.length || errors.skips.length || errors.failures.length || errors.malformed.length) {
    throw new Error(`reuse test occurrence mismatch; run=${errors.missingRuns}; pass=${errors.missingPasses}; unexpected-run=${errors.unexpectedRuns}; unexpected-pass=${errors.unexpectedPasses}; skip=${errors.skips}; failed=${errors.failures}; malformed=${errors.malformed}`);
  }
}

function selfTestReuseRunInventory() {
  const expected = ['TestReuseParser', 'TestReuseParser/nested'];
  const good = ['=== RUN   TestReuseParser', '=== RUN   TestReuseParser/nested', '    --- PASS: TestReuseParser/nested (0.00s)', '--- PASS: TestReuseParser (0.00s)'].join('\n');
  const cases = [
    { name: 'positive-indented-subtest', output: good, shouldPass: true },
    { name: 'missing', output: good.replace('    --- PASS: TestReuseParser/nested (0.00s)\n', ''), shouldPass: false },
    { name: 'skipped', output: good.replace('    --- PASS: TestReuseParser/nested', '    --- SKIP: TestReuseParser/nested'), shouldPass: false },
    { name: 'duplicate', output: `${good}\n    --- PASS: TestReuseParser/nested (0.00s)`, shouldPass: false },
    { name: 'unexpected', output: `${good}\n=== RUN   TestReuseParser/extra\n    --- PASS: TestReuseParser/extra (0.00s)`, shouldPass: false },
    { name: 'malformed-run', output: `${good}\n=== RUN   `, shouldPass: false },
    { name: 'malformed-pass-duration', output: `${good}\n--- PASS: TestUnexpected (unknown)`, shouldPass: false },
  ];
  for (const test of cases) {
    const errors = reuseInventoryErrors(test.output, expected);
    const failed = errors.missingRuns.length || errors.missingPasses.length || errors.unexpectedRuns.length || errors.unexpectedPasses.length || errors.skips.length || errors.failures.length || errors.malformed.length;
    if (Boolean(failed) === test.shouldPass) throw new Error(`reuse inventory parser self-test failed: ${test.name}`);
  }
}

selfTestReuseRunInventory();

function assertLifecycleScenarioCounters(output) {
  const evidence = 'lifecycle observable scenario counts: failed-start-reclaim=1 receipt-replacement=1 concurrent-commit-settlement=1 model-sync-retry=1 receipt-pin-failure=1 receipt-sync-retry=1';
  if (!output.includes(evidence)) throw new Error('lifecycle branch evidence is incomplete; expected exactly one execution of each of the six named lifecycle scenarios');
}

function linuxPath(winPath) {
  const normalized = path.resolve(winPath).replaceAll('\\', '/');
  const match = normalized.match(/^([A-Za-z]):(\/.*)$/);
  if (!match) throw new Error(`workspace path is not on a WSL-mounted drive: ${winPath}`);
  return `/mnt/${match[1].toLowerCase()}${match[2]}`;
}
function quote(value) { return `'${value.replaceAll("'", "'\\''")}'`; }

function assertOwnedStopRunInventory(output) {
  const expected = ownedStopTests;
  const positiveMarker = '__OWNED_STOP_G2_FIXTURE_POSITIVE__';
  if (output.split(positiveMarker).length - 1 !== 1) throw new Error('owned-stop G2 positive fixture marker is absent or duplicated');
  const runs = [], passes = [], skips = [], failures = [], malformed = [];
  for (const line of output.split(/\r?\n/)) {
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const match = line.match(/^=== RUN\s+(\S+)$/);
      if (!match) malformed.push(line); else runs.push(match[1]);
    }
    if (/^\s*--- (PASS|SKIP|FAIL):/.test(line)) {
      const match = line.match(/^--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)$/);
      if (!match) malformed.push(line);
      else if (match[1] === 'PASS') passes.push(match[2]);
      else if (match[1] === 'SKIP') skips.push(match[2]);
      else failures.push(match[2]);
    }
  }
  const runCounts = new Map(), passCounts = new Map();
  for (const name of runs) runCounts.set(name, (runCounts.get(name) ?? 0) + 1);
  for (const name of passes) passCounts.set(name, (passCounts.get(name) ?? 0) + 1);
  const missingRuns = expected.filter((name) => runCounts.get(name) !== 1);
  const missingPasses = expected.filter((name) => passCounts.get(name) !== 1);
  const unexpectedRuns = runs.filter((name) => !expected.includes(name));
  const unexpectedPasses = passes.filter((name) => !expected.includes(name));
  if (missingRuns.length || missingPasses.length || unexpectedRuns.length || unexpectedPasses.length || skips.length || failures.length || malformed.length) {
    throw new Error(`owned-stop RUN/PASS inventory mismatch: missing-run=${missingRuns}; missing-pass=${missingPasses}; skipped=${skips}; failed=${failures}; unexpected-run=${unexpectedRuns}; unexpected-pass=${unexpectedPasses}; malformed=${malformed}`);
  }
}

function assertRemoteTimeoutsStayInSupervisorGroup(runner, expectedCalls) {
  const timeoutCalls = [...runner.matchAll(/\btimeout\s+/g)].length;
  const foregroundCalls = [...runner.matchAll(/\btimeout\s+--foreground\b/g)].length;
  if (timeoutCalls !== expectedCalls || foregroundCalls !== timeoutCalls) {
    throw new Error(`remote runner timeout process-group oracle failed: calls=${timeoutCalls}, foreground=${foregroundCalls}, expected=${expectedCalls}`);
  }
}

function buildRemoteRunner({ selected, mutationBinaries }) {
  const regex = `^(${selected.join('|')})$`;
  const commands = [
    'set -euo pipefail',
    'umask 077',
    'base="$1"',
    'base_raw="$base"',
    'image="$base/verity.ext4"',
    'mnt="$base/mnt"',
    'cleanup(){ rc=$?; trap - EXIT HUP INT TERM; if [[ -d "$mnt" ]] && mountpoint -q -- "$mnt"; then if ! timeout --foreground --signal=TERM --kill-after=2s 8s umount -- "$mnt"; then echo "unmount failed; preserving exact scratch directory: $base" >&2; exit 1; fi; fi; if [[ -d "$mnt" ]] && mountpoint -q -- "$mnt"; then echo "mount remains active; preserving exact scratch directory: $base" >&2; exit 1; fi; exit "$rc"; }',
    'trap cleanup EXIT HUP INT TERM',
    'base=$(realpath -e -- "$base")',
    '[[ "$base" == "$base_raw" ]]',
    '[[ "$base" =~ ^/tmp/checkpoint-custody-upload[.][[:alnum:]_-]+$ ]]',
    '[[ "$(realpath -m -- "$image")" == "$base/verity.ext4" ]]',
    '[[ "$(realpath -m -- "$mnt")" == "$base/mnt" ]]',
    'image_identity="${CHECKPOINT_CUSTODY_IMAGE_IDENTITY:?receiver image identity is required}"',
    'mnt_identity="${CHECKPOINT_CUSTODY_MNT_IDENTITY:?receiver mountpoint identity is required}"',
    '[[ -d "$mnt" && ! -L "$mnt" && "$(stat -c "%d:%i:%u:%a" -- "$mnt")" == "$mnt_identity" ]]',
    '[[ "$image_identity" =~ ^[0-9]+:[0-9]+:0:[0-7]+:67108864$ ]]',
    'mount_fixture(){ [[ -f "$image" && ! -L "$image" && "$(realpath -e -- "$image")" == "$base/verity.ext4" ]] || { echo "owned image identity changed; preserving exact scratch directory: $base" >&2; return 1; }; [[ "$(stat -c "%d:%i:%u:%a:%s" -- "$image")" == "$image_identity" ]] || { echo "owned image identity changed; preserving exact scratch directory: $base" >&2; return 1; }; [[ -d "$mnt" && ! -L "$mnt" && "$(stat -c "%d:%i:%u:%a" -- "$mnt")" == "$mnt_identity" ]] || { echo "owned mountpoint identity changed; preserving exact scratch directory: $base" >&2; return 1; }; if mountpoint -q -- "$mnt"; then echo "refusing to format mounted image: $base" >&2; return 1; fi; timeout --foreground --signal=TERM --kill-after=2s 20s mkfs.ext4 -F -O verity -- "$image" >/dev/null; timeout --foreground --signal=TERM --kill-after=2s 20s mount -o loop -- "$image" "$mnt"; mountpoint -q -- "$mnt"; export CHECKPOINT_CUSTODY_VERITY_FILE="$mnt/model.bin"; printf "small fs-verity kernel fixture\\n" > "$CHECKPOINT_CUSTODY_VERITY_FILE"; sync "$CHECKPOINT_CUSTODY_VERITY_FILE"; export CHECKPOINT_CUSTODY_TEST_DIR="$mnt"; export TMPDIR="$mnt"; }',
    'unmount_fixture(){ if mountpoint -q -- "$mnt"; then timeout --foreground --signal=TERM --kill-after=2s 8s umount -- "$mnt" || { echo "unmount failed; preserving exact scratch directory: $base" >&2; return 1; }; fi; if mountpoint -q -- "$mnt"; then echo "mount remains active; preserving exact scratch directory: $base" >&2; return 1; fi; [[ -f "$image" && ! -L "$image" && "$(realpath -e -- "$image")" == "$base/verity.ext4" && "$(stat -c "%d:%i:%u:%a:%s" -- "$image")" == "$image_identity" ]] || { echo "owned image changed after unmount; preserving exact scratch directory: $base" >&2; return 1; }; [[ -d "$mnt" && ! -L "$mnt" && "$(stat -c "%d:%i:%u:%a" -- "$mnt")" == "$mnt_identity" ]] || { echo "owned mountpoint changed after unmount; preserving exact scratch directory: $base" >&2; return 1; }; }',
    'mount_fixture',
    `timeout --foreground --signal=TERM --kill-after=3s 55s "$2" -test.timeout=45s -test.v -test.run=${quote(regex)}`,
    'echo __CHECKPOINT_CUSTODY_MAIN_TESTS_DONE__',
    'unmount_fixture',
  ];
  for (let i = 0; i < mutationBinaries.length; i += 1) {
    const mutant = mutationBinaries[i];
    commands.push('mount_fixture');
    commands.push(`mkdir -- "$mnt/mutant-${i}"`);
    commands.push(`outputFile="$base/mutant-${i}.log"`);
    commands.push(`[[ -f "$outputFile" && ! -L "$outputFile" && "$(stat -c "%d:%i:%u:%a" -- "$outputFile")" == "$CHECKPOINT_CUSTODY_MUTANT_LOG_${i}_IDENTITY" ]] || { echo "owned mutant log identity changed; preserving exact scratch directory: $base" >&2; exit 1; }`);
    commands.push(`mutant_status=0; (ulimit -f 65536; CHECKPOINT_CUSTODY_TEST_DIR="$mnt/mutant-${i}" CHECKPOINT_CUSTODY_VERITY_FILE="$CHECKPOINT_CUSTODY_VERITY_FILE" timeout --foreground --signal=TERM --kill-after=3s 40s "$3/mutant-${i}.test" -test.timeout=30s -test.v -test.run=${quote(`^${mutant.test}$`)}) > "$outputFile" 2>&1 || mutant_status=$?; if [[ "$mutant_status" -ne 1 ]]; then echo "mutant exited $mutant_status instead of the expected assertion-failure status 1: ${mutant.test}" >&2; cat "$outputFile" >&2; exit 1; fi; [[ "$(stat -c %s -- "$outputFile")" -lt 67108864 ]] || { echo "mutant output reached its 64 MiB file limit: ${mutant.test}" >&2; exit 1; }`);
    commands.push(`grep -F -- ${quote(`--- FAIL: ${mutant.test}`)} "$outputFile" >/dev/null`);
    commands.push(`grep -F -- ${quote(mutant.expected)} "$outputFile" >/dev/null`);
    commands.push(`if grep -E 'panic:|no tests to run|build failed' "$outputFile" >/dev/null; then cat "$outputFile" >&2; exit 1; fi`);
    commands.push(`cat "$outputFile"`);
    commands.push('unmount_fixture');
  }
  const runner = `${commands.join('\n')}\n`;
  // Five fixed timeout commands cover cleanup, format, mount, unmount and the
  // main test binary; each mutant adds one more bounded timeout.
  assertRemoteTimeoutsStayInSupervisorGroup(runner, 5 + mutationBinaries.length);
  return runner;
}

function remoteReceiverSource() {
  return String.raw`import hashlib,json,os,signal,stat,struct,subprocess,sys,tempfile
MAX_MANIFEST=65536
MAX_FILE=67108864
MAX_TOTAL=268435456
MAX_WRITER_FILE=67108864
MAX_OUTPUT=67108864
# Conservative transaction file budget: <=256 MiB uploads + one 64 MiB image + runner.log and six mutant logs capped at 64 MiB each = 768 MiB, plus small filesystem metadata.
ALLOWED={'checkpoint-custody.test','runner.sh'}|{f'mutant-{i}.test' for i in range(6)}
SUPERVISOR=r'''import ctypes,os,signal,struct,subprocess,sys
runner,base,binary,control_fd,done_fd,parent_pid=sys.argv[1:]
control_fd=int(control_fd); done_fd=int(done_fd); parent_pid=int(parent_pid)
pending=None; child=None; parent_dead=False
def on_signal(signum,frame):
 global pending
 pending=signum
 if child is not None and child.poll() is None:
  try: child.send_signal(signum)
  except ProcessLookupError: pass
signal.signal(signal.SIGHUP,on_signal)
signal.signal(signal.SIGINT,on_signal)
signal.signal(signal.SIGTERM,on_signal)
def on_parent_death(signum,frame):
 global pending,parent_dead
 parent_dead=True
 pending=signal.SIGTERM
 try: os.killpg(os.getpgrp(),signal.SIGTERM)
 except ProcessLookupError: pass
signal.signal(signal.SIGUSR1,on_parent_death)
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(1,signal.SIGUSR1,0,0,0)!=0: raise OSError(ctypes.get_errno(),'PR_SET_PDEATHSIG failed')
if os.getppid()!=parent_pid: raise RuntimeError('receiver parent changed during supervisor startup')
def group_members():
 found=[]
 for proc_name in os.listdir('/proc'):
  if not proc_name.isdecimal() or int(proc_name)==os.getpid(): continue
  try:
   with open('/proc/'+proc_name+'/stat','r') as f: raw=f.read()
   fields=raw[raw.rfind(')')+2:].split()
  except (FileNotFoundError,ProcessLookupError,PermissionError): continue
  if len(fields)>2 and fields[2].isdecimal() and int(fields[2])==os.getpgrp(): found.append(int(proc_name))
 return found
if pending is None:
 child=subprocess.Popen(['/bin/bash',runner,base,binary,base],stdin=subprocess.DEVNULL,stdout=None,stderr=subprocess.STDOUT,close_fds=True,start_new_session=False)
 parent_dead_deadline=None
 while True:
  try: child_status=child.wait(timeout=0.1); break
  except subprocess.TimeoutExpired:
   if parent_dead:
    if parent_dead_deadline is None: parent_dead_deadline=__import__('time').monotonic()+5
    elif __import__('time').monotonic()>=parent_dead_deadline:
     try: os.killpg(os.getpgrp(),signal.SIGKILL)
     except ProcessLookupError: pass
     os._exit(125)
  except InterruptedError: continue
 members=group_members()
 if members:
  os.write(1,b'runner left child processes in its owned session; terminating that process group and failing closed\\n')
  try: os.killpg(os.getpgrp(),signal.SIGTERM)
  except ProcessLookupError: pass
  deadline=__import__('time').monotonic()+5
  while __import__('time').monotonic()<deadline:
   if not group_members(): break
   __import__('time').sleep(0.02)
  if group_members():
   # The supervisor is still the anchored session leader here. Killing the
   # group before it exits prevents a broken receiver pipe from orphaning a
   # TERM-resistant descendant; the receiver will observe EOF and preserve its nonce.
   try: os.killpg(os.getpgrp(),signal.SIGKILL)
   except ProcessLookupError: pass
   os._exit(125)
  child_status=125
 os.write(done_fd,struct.pack('!i',child_status)); os.close(done_fd)
 ready,_,_=__import__('select').select([control_fd],[],[],30)
 if ready:
  try: os.read(control_fd,1)
  except InterruptedError: pass
 if child is None: child_status=125
 os.close(control_fd)
if child is None: sys.exit(125)
sys.exit(child_status if child_status>=0 else 128-child_status)
'''
base=None
base_identity=None
base_fd=None
owned_registry={}
owned_fds={}
bash_identities={}
proc=None
control_write=None
done_read=None
interrupted=None
releasing=False
runner_complete=False
runner_status=None
group_completion_verified=False
def owned_identity(st):
 return (st.st_dev,st.st_ino,stat.S_IFMT(st.st_mode),st.st_uid,stat.S_IMODE(st.st_mode),st.st_nlink if stat.S_ISREG(st.st_mode) else None)
def hold_identity_fd(fd):
 expected=owned_identity(os.fstat(fd))
 path_only=getattr(os,'O_PATH',None)
 if path_only is None: raise RuntimeError('Linux O_PATH is required for non-writable nonce identity pins')
 held=os.open('/proc/self/fd/'+str(fd),path_only|getattr(os,'O_CLOEXEC',0))
 if owned_identity(os.fstat(held))!=expected:
  os.close(held)
  raise RuntimeError('nonce identity descriptor changed while pinning')
 return held
def remember_owned(name,st,fd):
 if name in owned_registry: raise RuntimeError('nonce object was registered more than once')
 owned_registry[name]=owned_identity(st)
 owned_fds[name]=hold_identity_fd(fd)
def bash_identity(st,include_size=False):
 value=f'{st.st_dev}:{st.st_ino}:{st.st_uid}:{stat.S_IMODE(st.st_mode):o}'
 return value+f':{st.st_size}' if include_size else value
def signal_owned_group(signum):
 if proc is not None and proc.poll() is None and not releasing:
  try: os.killpg(proc.pid,signum)
  except ProcessLookupError: pass
def on_signal(signum,frame):
 global interrupted
 interrupted=signum
 signal_owned_group(signum)
 if releasing: return
 raise InterruptedError('remote validation transport interrupted')
signal.signal(signal.SIGHUP,on_signal)
signal.signal(signal.SIGINT,on_signal)
signal.signal(signal.SIGTERM,on_signal)
def read_exact(fd,n,deadline):
 chunks=[]
 while n:
  left=deadline-__import__('time').monotonic()
  if left<=0 or not __import__('select').select([fd],[],[],left)[0]: raise TimeoutError('remote upload deadline exceeded')
  b=os.read(fd,min(n,1048576))
  if not b: raise EOFError('truncated upload frame')
  chunks.append(b); n-=len(b)
 return b''.join(chunks)
def copy_exact(fd,n,deadline,out,digest):
 while n:
  left=deadline-__import__('time').monotonic()
  if left<=0 or not __import__('select').select([fd],[],[],left)[0]: raise TimeoutError('remote upload deadline exceeded')
  b=os.read(fd,min(n,1048576))
  if not b: raise EOFError('truncated upload frame')
  digest.update(b); view=memoryview(b)
  while view:
   written=os.write(out,view)
   if written<=0: raise OSError('short local file write')
   view=view[written:]
  n-=len(b)
def writer_limit():
 import resource
 resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_WRITER_FILE,MAX_WRITER_FILE))
def wait_for_runner(deadline):
 global runner_complete,runner_status
 left=deadline-__import__('time').monotonic()
 if left<=0 or not __import__('select').select([done_read],[],[],left)[0]: raise TimeoutError('bounded remote runner deadline exceeded')
 data=b''
 while len(data)<4:
  part=os.read(done_read,4-len(data))
  if not part: raise EOFError('runner supervisor exited before completion status')
  data+=part
 runner_status=struct.unpack('!i',data)[0]; runner_complete=True
 return runner_status
def stop_owned_group(signum,grace):
 global releasing,control_write,group_completion_verified
 if proc is None: return
 if proc.poll() is not None:
  if not group_completion_verified: raise RuntimeError('runner supervisor exited before owned-group completion was verified; preserving the transaction')
  return
 if runner_complete and runner_status==125:
  signal_owned_group(signal.SIGKILL)
  try: proc.wait(timeout=3)
  except subprocess.TimeoutExpired: raise RuntimeError('owned runner group could not be reaped after orphan detection')
  raise RuntimeError('runner left descendants in its owned session; group was terminated and scratch preserved')
 if not runner_complete:
  signal_owned_group(signum)
  try: wait_for_runner(__import__('time').monotonic()+grace)
  except TimeoutError:
   if proc.poll() is None: signal_owned_group(signal.SIGKILL)
   try: proc.wait(timeout=3)
   except subprocess.TimeoutExpired: raise RuntimeError('owned runner supervisor could not be reaped after group kill')
   raise RuntimeError('runner group exceeded its cleanup grace; preserving the transaction')
 if control_write is not None:
  releasing=True
  try: os.write(control_write,b'R')
  finally: os.close(control_write); control_write=None; releasing=False
 try: proc.wait(timeout=5)
 except subprocess.TimeoutExpired:
  if proc.poll() is None:
   if not runner_complete: signal_owned_group(signal.SIGKILL)
   else: proc.kill()
  try: proc.wait(timeout=3)
  except subprocess.TimeoutExpired: raise RuntimeError('owned runner supervisor could not be reaped')
 expected_status=runner_status if runner_status>=0 else 128-runner_status
 if runner_complete and runner_status!=125 and proc.returncode==expected_status:
  group_completion_verified=True
 elif not group_completion_verified:
  raise RuntimeError('runner supervisor exit did not prove owned-group completion; preserving the transaction')
def remove_owned():
 global base_fd
 if base is None: return
 if proc is not None and not group_completion_verified:
  raise RuntimeError('owned-group completion was not verified; preserving the transaction')
 real=os.path.realpath(base)
 if real!=base or os.path.dirname(base)!='/tmp' or not __import__('re').fullmatch(r'/tmp/checkpoint-custody-upload[.][A-Za-z0-9_-]+',base):
  raise RuntimeError('receiver nonce path changed; preserving it')
 root_stat=os.lstat(base)
 if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or root_stat.st_uid!=os.geteuid() or root_stat.st_mode&0o077 or base_identity is None or base_fd is None or owned_identity(root_stat)!=base_identity or owned_identity(os.fstat(base_fd))!=base_identity:
  raise RuntimeError('receiver nonce directory authority changed; preserving it')
 entries=os.listdir(base)
 mnt=os.path.join(base,'mnt')
 if set(entries)!=set(owned_registry):
  raise RuntimeError('receiver nonce entry set changed; preserving it')
 if entries and 'mnt' not in owned_registry:
  raise RuntimeError('receiver nonce layout is incomplete; preserving it')
 if 'mnt' in owned_registry and (not os.path.lexists(mnt) or os.path.ismount(mnt)):
  raise RuntimeError('nonce mountpoint is missing or still mounted; preserving it')
 for name in entries:
  p=os.path.join(base,name); st=os.lstat(p)
  expected=owned_registry[name]
  held=owned_fds.get(name)
  if held is None or owned_identity(st)!=expected or owned_identity(os.fstat(held))!=expected:
   raise RuntimeError('nonce object identity changed; preserving it')
  if name=='verity.ext4' and st.st_size!=67108864:
   raise RuntimeError('nonce image size changed; preserving it')
  if name=='mnt':
   if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or os.listdir(p):
    raise RuntimeError('nonce mountpoint is not an empty owned directory; preserving it')
  elif not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
   raise RuntimeError('nonce contains a non-regular owned object; preserving it')
 # Validate the complete registry before removing even the first entry.
 for name in entries:
  if name!='mnt': os.unlink(os.path.join(base,name))
 if 'mnt' in owned_registry: os.rmdir(mnt)
 os.rmdir(base)
 for fd in owned_fds.values(): os.close(fd)
 owned_fds.clear()
 os.close(base_fd)
 base_fd=None
def main():
 global base,base_identity,base_fd,proc,control_write,done_read,releasing,group_completion_verified
 base=tempfile.mkdtemp(prefix='checkpoint-custody-upload.',dir='/tmp')
 try:
  os.chmod(base,0o700)
  base_fd=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)); base_identity=owned_identity(os.fstat(base_fd))
  fdin=sys.stdin.fileno(); upload_deadline=__import__('time').monotonic()+300
  header=read_exact(fdin,4,upload_deadline)
  n=struct.unpack('!I',header)[0]
  if n<2 or n>MAX_MANIFEST: raise ValueError('manifest length outside bound')
  manifest=json.loads(read_exact(fdin,n,upload_deadline))
  if not isinstance(manifest,dict) or set(manifest)!={'files'} or not isinstance(manifest['files'],list): raise ValueError('invalid manifest schema')
  files=manifest['files']; names=[]; total=0
  if len(files)<2 or len(files)>8: raise ValueError('manifest entry count outside bound')
  for item in files:
   if not isinstance(item,dict) or set(item)!={'name','size','sha256'}: raise ValueError('invalid manifest entry')
   name=item['name']; size=item['size']; digest=item['sha256']
   if name not in ALLOWED or name in names or type(size) is not int or size<1 or size>MAX_FILE or not isinstance(digest,str) or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest): raise ValueError('manifest entry outside allowlist or bounds')
   names.append(name); total+=size
  mutant_names={name for name in names if name.startswith('mutant-')}
  expected_names={'checkpoint-custody.test','runner.sh'}|{f'mutant-{i}.test' for i in range(len(mutant_names))}
  if set(names)!=expected_names or total>MAX_TOTAL: raise ValueError('manifest total or file set invalid')
  mnt_path=os.path.join(base,'mnt'); os.mkdir(mnt_path,0o700); mnt_fd=os.open(mnt_path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))
  try: mnt_stat=os.fstat(mnt_fd); remember_owned('mnt',mnt_stat,mnt_fd); bash_identities['mnt']=bash_identity(mnt_stat)
  finally: os.close(mnt_fd)
  image_path=os.path.join(base,'verity.ext4')
  image_fd=os.open(image_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  try:
   os.ftruncate(image_fd,67108864); os.fsync(image_fd); image_stat=os.fstat(image_fd); remember_owned('verity.ext4',image_stat,image_fd); bash_identities['verity.ext4']=bash_identity(image_stat,True)
  finally: os.close(image_fd)
  for i in range(len(mutant_names)):
   name=f'mutant-{i}.log'; fd=os.open(os.path.join(base,name),os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
   try:
    log_stat=os.fstat(fd); remember_owned(name,log_stat,fd); bash_identities[name]=bash_identity(log_stat)
   finally: os.close(fd)
  for item in files:
   name=item['name']; size=item['size']; expected=item['sha256']
   flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
   out=os.open(os.path.join(base,name),flags,0o600); h=hashlib.sha256()
   try:
    if name.endswith('.test'): os.fchmod(out,0o700)
    remember_owned(name,os.fstat(out),out)
    copy_exact(fdin,size,upload_deadline,out,h); os.fsync(out)
   finally: os.close(out)
   if h.hexdigest()!=expected: raise ValueError('uploaded file hash mismatch')
  left=upload_deadline-__import__('time').monotonic()
  if left<=0 or not __import__('select').select([fdin],[],[],left)[0]: raise TimeoutError('remote upload EOF deadline exceeded')
  if os.read(fdin,1): raise ValueError('trailing upload bytes')
  runner=os.path.join(base,'runner.sh'); binary=os.path.join(base,'checkpoint-custody.test')
  for p in (runner,binary):
   st=os.lstat(p)
   if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode): raise ValueError('staged path is not regular')
  log_path=os.path.join(base,'runner.log')
  log_fd=os.open(log_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
  remember_owned('runner.log',os.fstat(log_fd),log_fd)
  log_file=os.fdopen(log_fd,'wb')
  control_read,control_write=os.pipe(); done_read,done_write=os.pipe()
  runner_env=os.environ.copy()
  runner_env['CHECKPOINT_CUSTODY_IMAGE_IDENTITY']=bash_identities['verity.ext4']
  runner_env['CHECKPOINT_CUSTODY_MNT_IDENTITY']=bash_identities['mnt']
  for i in range(len(mutant_names)):
   runner_env[f'CHECKPOINT_CUSTODY_MUTANT_LOG_{i}_IDENTITY']=bash_identities[f'mutant-{i}.log']
  try:
   try: proc=subprocess.Popen([sys.executable,'-c',SUPERVISOR,runner,base,binary,str(control_read),str(done_write),str(os.getpid())],stdin=subprocess.DEVNULL,stdout=log_file,stderr=subprocess.STDOUT,close_fds=True,pass_fds=(control_read,done_write),start_new_session=True,preexec_fn=writer_limit,env=runner_env)
   except BaseException:
    os.close(control_write); control_write=None
    os.close(done_read); done_read=None
    raise
  finally:
   os.close(control_read); os.close(done_write)
  # Seven bounded fixture cycles (main + six mutants) need up to ~635 s; keep an explicit transaction-wide runner deadline above that sum.
  runner_status=wait_for_runner(__import__('time').monotonic()+700)
  if runner_status==125: raise RuntimeError('runner left descendants in its owned session')
  releasing=True
  os.write(control_write,b'R'); os.close(control_write); control_write=None
  try: proc.wait(timeout=5)
  except subprocess.TimeoutExpired:
   if proc.poll() is None: proc.kill()
   try: proc.wait(timeout=3)
   except subprocess.TimeoutExpired: raise RuntimeError('runner supervisor was not reaped after release')
  finally: releasing=False
  os.close(done_read); done_read=None
  log_file.close()
  expected_supervisor_status=runner_status if runner_status>=0 else 128-runner_status
  if proc.returncode!=expected_supervisor_status: raise RuntimeError('runner supervisor status disagreed with its child status')
  if runner_status==125: raise RuntimeError('runner group completion was not verified')
  group_completion_verified=True
  log_stat=os.lstat(log_path)
  if not stat.S_ISREG(log_stat.st_mode) or stat.S_ISLNK(log_stat.st_mode) or log_stat.st_size>=MAX_OUTPUT: raise ValueError('remote validation output reached its enforced 64 MiB RLIMIT_FSIZE bound')
  log_fd=os.open(log_path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  try: output=os.read(log_fd,MAX_OUTPUT+1)
  finally: os.close(log_fd)
  if len(output)>=MAX_OUTPUT: raise ValueError('remote validation output reached its enforced 64 MiB RLIMIT_FSIZE bound')
  if runner_status!=0: raise RuntimeError('remote validation runner failed with status '+str(runner_status)+'\n'+output.decode('utf-8','replace'))
  if b'__CHECKPOINT_CUSTODY_MAIN_TESTS_DONE__' not in output: raise RuntimeError('main test completion marker missing')
  if interrupted is not None: raise InterruptedError('remote validation transport interrupted during supervisor release')
  remove_owned(); base=None
  sys.stdout.buffer.write(output); sys.stdout.buffer.write(b'\n__CHECKPOINT_CUSTODY_REMOTE_CLEANUP_CONFIRMED__\n'); sys.stdout.buffer.flush()
 except BaseException:
  try:
   stop_owned_group(signal.SIGTERM,70)
  except Exception as e:
   if done_read is not None:
    try: os.close(done_read); done_read=None
    except OSError: pass
   if control_write is not None:
    try: os.close(control_write); control_write=None
    except OSError: pass
   if 'log_file' in locals() and not log_file.closed: log_file.close()
   print('runner process group could not be fully reaped; exact nonce directory preserved at '+str(base)+': '+str(e),file=sys.stderr)
   raise
  if done_read is not None:
   try: os.close(done_read); done_read=None
   except OSError: pass
  if control_write is not None:
   try: os.close(control_write); control_write=None
   except OSError: pass
  if 'log_file' in locals() and not log_file.closed: log_file.close()
  try: remove_owned(); base=None
  except Exception as e: print('cleanup failed; exact nonce directory preserved at '+str(base)+': '+str(e),file=sys.stderr)
  raise
if __name__=='__main__':
 try: main()
 except Exception as e: print('remote custody transport failed: '+str(e),file=sys.stderr); sys.exit(1)
`;
}

function assertReceiverIdentityPinsAreReadOnly(source) {
  const usesPathOnly = /path_only=getattr\(os,'O_PATH',None\)[\s\S]*?os\.open\('\/proc\/self\/fd\/'\+str\(fd\),path_only\|getattr\(os,'O_CLOEXEC',0\)\)/.test(source);
  const verifiesPinnedIdentity = /owned_identity\(os\.fstat\(held\)\)!=expected/.test(source);
  const usesPinnedHandle = /owned_fds\[name\]=hold_identity_fd\(fd\)/.test(source);
  if (!usesPathOnly || !verifiesPinnedIdentity || !usesPinnedHandle || /owned_fds\[name\]=os\.dup\(fd\)/.test(source)) {
    throw new Error('receiver identity pin oracle failed: uploaded executables must remain pinned without writable descriptors');
  }
}

assertReceiverIdentityPinsAreReadOnly(remoteReceiverSource());

function buildRemotePayload(binaryPath, runner, mutationBinaries) {
  const files = [
    { name: 'checkpoint-custody.test', data: readFileSync(binaryPath) },
    ...mutationBinaries.map((mutation, i) => ({ name: `mutant-${i}.test`, data: readFileSync(mutation.local) })),
    { name: 'runner.sh', data: Buffer.from(runner, 'utf8') },
  ];
  const entries = files.map(({ name, data }) => ({ name, size: data.length, sha256: createHash('sha256').update(data).digest('hex') }));
  const manifest = Buffer.from(JSON.stringify({ files: entries }), 'utf8');
  if (manifest.length > 65536 || files.some(({ data }) => data.length > 64 * 1024 * 1024) || files.reduce((sum, f) => sum + f.data.length, 0) > 256 * 1024 * 1024) {
    throw new Error('remote validation payload exceeds transport bounds');
  }
  return Buffer.concat([Buffer.from([(manifest.length >>> 24) & 255, (manifest.length >>> 16) & 255, (manifest.length >>> 8) & 255, manifest.length & 255]), manifest, ...files.map((f) => f.data)]);
}

function buildFailurePayload({ fileBytes, binaryHash, trailing = false, truncateAfterBinary = false }) {
  const runnerBytes = Buffer.from('#!/bin/bash\n', 'utf8');
  const binary = fileBytes;
  const files = [
    { name: 'checkpoint-custody.test', data: binary, size: 3, sha256: binaryHash ?? createHash('sha256').update(Buffer.from('abc')).digest('hex') },
    { name: 'runner.sh', data: runnerBytes, size: runnerBytes.length, sha256: createHash('sha256').update(runnerBytes).digest('hex') },
  ];
  const manifest = Buffer.from(JSON.stringify({ files: files.map(({ name, size, sha256 }) => ({ name, size, sha256 })) }), 'utf8');
  const body = truncateAfterBinary ? [binary] : files.map((item) => item.data);
  const framed = Buffer.concat([Buffer.from([(manifest.length >>> 24) & 255, (manifest.length >>> 16) & 255, (manifest.length >>> 8) & 255, manifest.length & 255]), manifest, ...body]);
  return trailing ? Buffer.concat([framed, Buffer.from([0x58])]) : framed;
}

function runTransportFailureSelfTests() {
  const selfTestRoot = mkdtempSync(path.join(root, '.tmp-checkpoint-custody-transport-'));
  for (const mutantCount of [0, 6]) {
    buildRemoteRunner({
      selected: ['TestCheckpointCustodyTransportTimeoutGroupOracle'],
      mutationBinaries: Array.from({ length: mutantCount }, (_, i) => ({ test: `TestCheckpointCustodyMutation${i}`, expected: 'expected rejection' })),
    });
  }
  const cases = [
    { name: 'truncated-header', input: Buffer.alloc(0), expected: 'EOFError', expectedMessage: 'truncated upload frame' },
    { name: 'truncated-file', input: buildFailurePayload({ fileBytes: Buffer.from('a'), truncateAfterBinary: true }), expected: 'EOFError', expectedMessage: 'truncated upload frame' },
    { name: 'hash-mismatch', input: buildFailurePayload({ fileBytes: Buffer.from('abc'), binaryHash: '0'.repeat(64) }), expected: 'ValueError', expectedMessage: 'uploaded file hash mismatch' },
    { name: 'trailing-bytes', input: buildFailurePayload({ fileBytes: Buffer.from('abc'), trailing: true }), expected: 'ValueError', expectedMessage: 'trailing upload bytes' },
    { name: 'expired-upload-deadline', input: Buffer.alloc(0), expected: 'TimeoutError', expectedMessage: 'remote upload deadline exceeded', expireImmediately: true },
  ];
  try {
    for (const test of cases) {
      let source = remoteReceiverSource()
        .replace("path_only=getattr(os,'O_PATH',None)\n if path_only is None: raise RuntimeError('Linux O_PATH is required for non-writable nonce identity pins')\n held=os.open('/proc/self/fd/'+str(fd),path_only|getattr(os,'O_CLOEXEC',0))", "held=os.dup(fd)")
        .replace("base=tempfile.mkdtemp(prefix='checkpoint-custody-upload.',dir='/tmp')", `base=tempfile.mkdtemp(prefix='checkpoint-custody-upload.',dir=${JSON.stringify(selfTestRoot)})`)
        .replace("if real!=base or os.path.dirname(base)!='/tmp' or not __import__('re').fullmatch(r'/tmp/checkpoint-custody-upload[.][A-Za-z0-9_-]+',base):", `if real!=base or os.path.normcase(os.path.dirname(base))!=os.path.normcase(${JSON.stringify(selfTestRoot)}) or not os.path.basename(base).startswith('checkpoint-custody-upload.'):`)
        .replace("base_fd=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)); base_identity=owned_identity(os.fstat(base_fd))", "base_fd=os.dup(0); base_identity=owned_identity(os.lstat(base))")
        .replace(" or owned_identity(os.fstat(base_fd))!=base_identity", "")
        .replace("if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or root_stat.st_uid!=os.geteuid() or root_stat.st_mode&0o077 or base_identity is None or base_fd is None or owned_identity(root_stat)!=base_identity:", "if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or base_identity is None or base_fd is None or owned_identity(root_stat)!=base_identity:")
        .replace("mnt_path=os.path.join(base,'mnt'); os.mkdir(mnt_path,0o700); mnt_fd=os.open(mnt_path,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0))\n  try: mnt_stat=os.fstat(mnt_fd); remember_owned('mnt',mnt_stat,mnt_fd); bash_identities['mnt']=bash_identity(mnt_stat)\n  finally: os.close(mnt_fd)", "mnt_path=os.path.join(base,'mnt'); os.mkdir(mnt_path,0o700); mnt_stat=os.lstat(mnt_path); owned_registry['mnt']=owned_identity(mnt_stat); bash_identities['mnt']=bash_identity(mnt_stat)")
        .replace("if held is None or owned_identity(st)!=expected or owned_identity(os.fstat(held))!=expected:", "if (held is None and name!='mnt') or owned_identity(st)!=expected or (held is not None and owned_identity(os.fstat(held))!=expected):")
        .replace(" # Validate the complete registry before removing even the first entry.", " for fd in owned_fds.values(): os.close(fd)\n owned_fds.clear()")
        .replace("if name.endswith('.test'): os.fchmod(out,0o700)", "if name.endswith('.test') and hasattr(os,'fchmod'): os.fchmod(out,0o700)")
        .replaceAll('signal.signal(signal.SIGHUP,on_signal)', 'signal.signal(signal.SIGINT,on_signal)')
        .replace('signal.signal(signal.SIGUSR1,on_parent_death)', 'signal.signal(signal.SIGINT,on_parent_death)')
        .replace("upload_deadline=__import__('time').monotonic()+300", `upload_deadline=__import__('time').monotonic()+${test.expireImmediately ? '0' : '300'}`);
      const receiverB64 = Buffer.from(source, 'utf8').toString('base64');
      const harness = [
        'import base64,os,sys,types',
        'sys.modules["select"]=types.SimpleNamespace(select=lambda readers,writers,errors,timeout:(readers,[],[]))',
        `source=base64.b64decode('${receiverB64}')`,
        "ns={'__name__':'receiver_failure_test'}",
        "exec(compile(source,'<receiver-failure-test>','exec'),ns)",
        "compile(ns['SUPERVISOR'],'<runner-supervisor-test>','exec')",
        'created=[]',
        'original=ns["tempfile"].mkdtemp',
        'def tracked(*args,**kwargs):',
        ' p=original(*args,**kwargs); created.append(p); return p',
        'ns["tempfile"].mkdtemp=tracked',
        'try:',
        ' ns["main"]()',
        ' print("receiver unexpectedly accepted invalid frame",file=sys.stderr); sys.exit(1)',
        'except Exception as exc:',
        ` if type(exc).__name__!="${test.expected}" or ${JSON.stringify(test.expectedMessage)} not in str(exc): print("wrong failure: "+type(exc).__name__+": "+str(exc),file=sys.stderr); sys.exit(2)`,
        ' if len(created)!=1 or os.path.lexists(created[0]): print("receiver left its owned nonce directory",file=sys.stderr); sys.exit(3)',
        ` print("${test.name}: cleanup confirmed")`,
      ].join('\n');
      const result = spawnSync('python', ['-c', harness], {
        cwd: root, encoding: 'utf8', input: test.input, timeout: 15_000, maxBuffer: 64 * 1024,
      });
      if (result.error) throw result.error;
      const output = (result.stdout ?? '') + (result.stderr ?? '');
      if (result.status !== 0 || !output.includes(`${test.name}: cleanup confirmed`)) {
        throw new Error(`local receiver failure test ${test.name} failed (status=${result.status}): ${output}`);
      }
    }
    for (const test of [
      { name: 'cleanup-unknown-entry', reason: 'entry set changed', extra: true, swap: false },
      { name: 'cleanup-replaced-inode', reason: 'object identity changed', extra: false, swap: true },
    ]) {
      let source = remoteReceiverSource()
        .replace("path_only=getattr(os,'O_PATH',None)\n if path_only is None: raise RuntimeError('Linux O_PATH is required for non-writable nonce identity pins')\n held=os.open('/proc/self/fd/'+str(fd),path_only|getattr(os,'O_CLOEXEC',0))", "held=os.dup(fd)")
        .replace("base=tempfile.mkdtemp(prefix='checkpoint-custody-upload.',dir='/tmp')", `base=tempfile.mkdtemp(prefix='checkpoint-custody-upload.',dir=${JSON.stringify(selfTestRoot)})`)
        .replace("if real!=base or os.path.dirname(base)!='/tmp' or not __import__('re').fullmatch(r'/tmp/checkpoint-custody-upload[.][A-Za-z0-9_-]+',base):", `if real!=base or os.path.normcase(os.path.dirname(base))!=os.path.normcase(${JSON.stringify(selfTestRoot)}) or not os.path.basename(base).startswith('checkpoint-custody-upload.'):`)
        .replace("if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or root_stat.st_uid!=os.geteuid() or root_stat.st_mode&0o077 or base_identity is None or base_fd is None or owned_identity(root_stat)!=base_identity or owned_identity(os.fstat(base_fd))!=base_identity:", "if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or base_identity is None or base_fd is None or owned_identity(root_stat)!=base_identity or owned_identity(os.fstat(base_fd))!=base_identity:")
        .replace("base_fd=os.open(base,os.O_RDONLY|getattr(os,'O_DIRECTORY',0)|getattr(os,'O_NOFOLLOW',0)); base_identity=owned_identity(os.fstat(ns[\"base_fd\"]))", "base_fd=os.dup(0); base_identity=owned_identity(os.lstat(base))")
        .replace(" or owned_identity(os.fstat(base_fd))!=base_identity", "")
        .replace("if entries and 'mnt' not in owned_registry:", "if False:")
        .replaceAll('signal.signal(signal.SIGHUP,on_signal)', 'signal.signal(signal.SIGINT,on_signal)')
        .replace('signal.signal(signal.SIGUSR1,on_parent_death)', 'signal.signal(signal.SIGINT,on_parent_death)')
        .replace(" # Validate the complete registry before removing even the first entry.", " for fd in owned_fds.values(): os.close(fd)\n owned_fds.clear()");
      const receiverB64 = Buffer.from(source, 'utf8').toString('base64');
      const harness = [
        'import base64,os,sys,stat',
        `source=base64.b64decode('${receiverB64}')`,
        "ns={'__name__':'receiver_cleanup_test'}",
        "exec(compile(source,'<receiver-cleanup-test>','exec'),ns)",
        `case=${JSON.stringify(test.name)}`,
        `base=os.path.join(${JSON.stringify(selfTestRoot)},'checkpoint-custody-upload.'+case)`,
        'os.mkdir(base,0o700); ns["base"]=base; ns["base_fd"]=os.dup(0); ns["base_identity"]=ns["owned_identity"](os.lstat(base))',
        'owned=os.path.join(base,"tracked.bin"); fd=os.open(owned,os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600); ns["remember_owned"]("tracked.bin",os.fstat(fd),fd); os.close(fd)',
        test.extra ? 'open(os.path.join(base,"mutant-99.log"),"xb").close()' : 'replacement=os.path.join(os.path.dirname(base),"replacement-"+case+".bin"); open(replacement,"xb").close(); ns["owned_registry"]["tracked.bin"]=ns["owned_identity"](os.lstat(replacement))',
        'try:',
        ' ns["remove_owned"](); print("cleanup accepted a changed ownership fixture",file=sys.stderr); sys.exit(1)',
        'except RuntimeError as exc:',
        ` if ${JSON.stringify(test.reason)} not in str(exc): print("wrong cleanup refusal: "+str(exc),file=sys.stderr); sys.exit(2)`,
        ` if not os.path.isdir(base) or not os.path.exists(owned)${test.extra ? ' or not os.path.exists(os.path.join(base,"mutant-99.log"))' : ''}: print("cleanup removed or lost changed ownership evidence",file=sys.stderr); sys.exit(3)`,
        ' print(case+": refusal preserved the nonce")',
        'finally:',
        ' if os.path.isdir(base):',
        '  for fd in ns["owned_fds"].values(): os.close(fd)',
        '  os.close(ns["base_fd"])',
        '  replacement=os.path.join(os.path.dirname(base),"replacement-"+case+".bin")',
        '  for name in ("tracked.bin","mutant-99.log"): ',
        '   p=os.path.join(base,name)',
        '   if os.path.exists(p): os.unlink(p)',
        '  if os.path.exists(replacement): os.unlink(replacement)',
        '  os.rmdir(base)',
      ].join('\n');
      const result = spawnSync('python', ['-c', harness], {
        cwd: root, encoding: 'utf8', timeout: 15_000, maxBuffer: 64 * 1024,
      });
      if (result.error) throw result.error;
      const output = (result.stdout ?? '') + (result.stderr ?? '');
      if (result.status !== 0 || !output.includes(`${test.name}: refusal preserved the nonce`)) {
        throw new Error(`local receiver cleanup ownership test ${test.name} failed (status=${result.status}): ${output}`);
      }
    }
    console.log('checkpoint custody transport failure-path self-test passed');
  } finally {
    try { rmdirSync(selfTestRoot); } catch (error) {
      if (error.code !== 'ENOTEMPTY' && error.code !== 'EEXIST') throw error;
      process.stderr.write(`transport self-test left evidence in ${selfTestRoot}; directory preserved\n`);
    }
  }
}

if (mode.includes('--transport-self-test')) {
  runTransportFailureSelfTests();
  process.exit(0);
}

const temp = mkdtempSync(path.join(root, '.tmp-checkpoint-custody-'));
try {
  if (process.platform !== 'win32') throw new Error('Linux custody gates execute through the reviewed Ubuntu WSL distribution on Windows');
  const binary = path.join(temp, 'nodeagent-linux.test');
  run('go', ['test', '-c', '-o', binary, './internal/nodeagent'], { env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64' } });
  const linuxBin = linuxPath(binary);
  const kernelOnly = mode.includes('--kernel');
  const lifecycleOnly = mode.includes('--lifecycle');
  const selected = selectCustodyTests(mode);
  const regex = `^(${selected.join('|')})$`;
  const mutationBinaries = [];
  if (mode.includes('--faults')) {
    const genericPath = path.join(root, 'internal/nodeagent/checkpoint_custody.go');
    const generic = readFileSync(genericPath, 'utf8');
    const linuxPathSource = path.join(root, 'internal/nodeagent/checkpoint_custody_linux.go');
    const linuxSource = readFileSync(linuxPathSource, 'utf8');
    const ownedStopLinuxPathSource = path.join(root, 'internal/nodeagent/checkpoint_unit_lifecycle_linux.go');
    const ownedStopLinuxSource = readFileSync(ownedStopLinuxPathSource, 'utf8');
    const custodyMutations = [
      { file: genericPath, source: generic, name: 'TestCheckpointCustodyBeginRequiresExactlyOneModelPlaceholder', expected: 'custody rejection assertion: missing model placeholder was not rejected by model-argument validation', pattern: /if modelArg < 0 \{\s*return nil, errors\.New\("controlled launch command must name the prepared model with -m or --model"\)\s*\}/, replacement: 'if false { return nil, errors.New("controlled launch command must name the prepared model with -m or --model") }' },
      { file: genericPath, source: generic, name: 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering', expected: 'custody rejection assertion: reused prepared source was not rejected by single-use validation', pattern: /if model\.used \{\s*model\.mu\.Unlock\(\)\s*return nil, errors\.New\("prepared source has already been used"\)\s*\}/, replacement: 'if false { model.mu.Unlock(); return nil, errors.New("prepared source has already been used") }' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering', expected: 'custody rejection assertion: forged receipt verified', pattern: /if e != nil \|\| !ed25519\.Verify\(pub, b, sig\) \{\s*continue\s*\}/, replacement: 'if len(b) < 0 || len(sig) < 0 || e != nil { continue }' },
      { file: genericPath, source: generic, name: 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering', expected: 'custody rejection assertion: model pathname replacement redirected the controlled child', changes: [
        { pattern: /l\.cmd\.Args\[i\] = "\/proc\/self\/fd\/4"/, replacement: 'l.cmd.Args[i] = l.model.path' },
        { pattern: /if !containsExact\(l\.cmd\.Args, "\/proc\/self\/fd\/4"\) \{/, replacement: 'if !containsExact(l.cmd.Args, l.model.path) {' },
      ] },
      { file: genericPath, source: generic, name: 'TestCheckpointCustodyLinuxManagedLaunchReceiptAndRejectsTampering', expected: 'custody rejection assertion: replaced executable pathname launched despite pinned inode mismatch', pattern: /if err := validateCheckpointLaunchExecutablePlatform\(l\.executablePath, l\.expectedExecutableSHA256, l\.cmd\.ExtraFiles\[0\]\); err != nil \{\s*return err\s*\}/, replacement: 'if false { return errors.New("skipped executable launch-path revalidation") }' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyClockAuthorityUsesBootTimeAndBootIDOnly', expected: 'custody rejection assertion: clock authority must exclusively use CLOCK_BOOTTIME and kernel boot ID', pattern: /func checkpointCustodyClockID\(\) int32\s+\{\s*return unix\.CLOCK_BOOTTIME\s*\}/, replacement: 'func checkpointCustodyClockID() int32 { return unix.CLOCK_REALTIME }' },
    ];
    const lifecycleMutations = [
      { file: genericPath, source: generic, name: 'TestCheckpointCustodyLifecycleExactReleaseCycles', expected: 'lifecycle rejection assertion: active child source released before exact reap', changes: [
        { pattern: /if !l\.terminal \|\| l\.aborting \|\| l\.committing \|\| l\.commitDone != nil \|\| \(l\.started && !l\.reaped && !l\.aborted\) \{\s*l\.mu\.Unlock\(\)\s*done <- errors\.New\("controlled launch has no settled terminal ownership"\)\s*return\s*\}/, replacement: 'if false { l.mu.Unlock(); done <- errors.New("controlled launch has no settled terminal ownership"); return }' },
        { pattern: /if l\.committed && !l\.reaped \{\s*l\.mu\.Unlock\(\)\s*done <- errors\.New\("committed child must be exactly reaped before source release"\)\s*return\s*\}/, replacement: 'if false { l.mu.Unlock(); done <- errors.New("committed child must be exactly reaped before source release"); return }' },
      ] },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyLifecycleRejectsReplacedModel', expected: 'lifecycle rejection assertion: replaced model inode passed exact path verification', pattern: /if pathStat\.Dev != pinStat\.Dev \|\| pathStat\.Ino != pinStat\.Ino \|\| pathStat\.Size != pinStat\.Size \|\| pathStat\.Nlink != 1 \|\| pinStat\.Nlink != 1 \|\| uint32\(pathStat\.Uid\) != uint32\(os\.Getuid\(\)\) \|\| pathStat\.Mode&0777 != 0600 \{\s*return errors\.New\("staged model path no longer names the original private inode"\)\s*\}/, replacement: 'if false { return errors.New("staged model path no longer names the original private inode") }' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyLifecycleCapturePreservesPreCaptureReplacement', expected: 'lifecycle capture assertion: pre-capture replacement was removed', pattern: /if a\.Mode&syscall\.S_IFMT != syscall\.S_IFREG \|\| a\.Dev != b\.Dev \|\| a\.Ino != b\.Ino \|\| a\.Size != b\.Size \|\| a\.Uid != b\.Uid \|\| a\.Mode&0777 != b\.Mode&0777 \|\| a\.Nlink != 1 \{\s*return errors\.New\("captured entry identity differs from original held inode"\)\s*\}/, replacement: 'if false { return errors.New("captured entry identity differs from original held inode") }' },
    ];
    const controlledSourceMutations = [
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointControlledSourceReceiptJSONIsStrict', expected: 'accepted malformed controlled receipt: unknown', pattern: /if !ok \|\| !exactJSONKeys\(root, "receipt", "signature"\) \{\s*return errors\.New\("controlled receipt envelope has unknown or missing fields"\)\s*\}/, replacement: 'if false { return errors.New("controlled receipt envelope has unknown or missing fields") }' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping', expected: 'controlled source FIFO descriptor rejection exceeded its bound', pattern: /unix\.Open\(fdPath, unix\.O_RDONLY\|unix\.O_CLOEXEC\|unix\.O_NONBLOCK, 0\)/, replacement: 'unix.Open(fdPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping', expected: 'controlled receipt signature-tamper was accepted', pattern: /if e != nil \|\| !ed25519\.Verify\(pub, b, sig\) \{\s*continue\s*\}/, replacement: 'if e != nil || len(b) < 0 || len(sig) < 0 { continue }' },
      { file: path.join(root, 'internal/nodeagent/checkpoint_identity_linux.go'), source: readFileSync(path.join(root, 'internal/nodeagent/checkpoint_identity_linux.go'), 'utf8'), name: 'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping', expected: 'generic full-mapping identity observer accepted the same unmapped/partial child', changes: [
        { pattern: /checkpointVerifyModelMapped\(ctx, filepath\.Join\(procDir, "maps"\), model\.device, model\.inode, model\.size\)/g, replacement: 'checkpointMeasureModelMapped(ctx, filepath.Join(procDir, "maps"), model.device, model.inode, model.size)' },
      ] },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointControlledSourcePrivateChildVerifiesWithoutMapping', expected: 'terminal release accepted a mutated retained executable identity', pattern: /versionOK = l\.controlledExecutablePinned && \*r\.Executable == l\.controlledExecutableIdentity/, replacement: 'versionOK = true' },
    ];
    const reuseMutations = [
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyReuseFreshProcessesNoCopy', expected: 'actual copy branch bytes for process 0', pattern: /s\.reuseCopyBytesTest\(n\)/, replacement: 's.reuseCopyBytesTest(0)' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyReuseRejectsOrphansAndTampering', expected: 'corrupt, orphaned, or substituted cache state was accepted', pattern: /if err != nil \|\| len\(sig\) != ed25519\.SignatureSize \|\| hex\.EncodeToString\(sig\) != signed\.Signature \|\| !ed25519\.Verify\(pub, payload, sig\) \{\s*return nil, custodySourceIdentity\{\}, errors\.New\("reusable cache record signature is invalid"\)\s*\}/, replacement: 'if err != nil || len(sig) != ed25519.SignatureSize || hex.EncodeToString(sig) != signed.Signature || (ed25519.Verify(pub, payload, sig) && false) { return nil, custodySourceIdentity{}, errors.New("reusable cache record signature is invalid") }' },
      { file: linuxPathSource, source: linuxSource, name: 'TestCheckpointCustodyReuseFreshProcessesNoCopy', expected: 'terminal cleanup removed reusable model', pattern: /if l\.model\.reusable \{\s*if err = verifyCustodyModelPath\(l\.model\); err != nil \{\s*return err\s*\}/, replacement: 'if false { if err = verifyCustodyModelPath(l.model); err != nil { return err }' },
    ];
    const ownedStopMutations = [
      { file: path.join(root, 'internal/nodeagent/commands.go'), source: readFileSync(path.join(root, 'internal/nodeagent/commands.go'), 'utf8'), name: 'TestCheckpointFixedOwnedStopRemoteKernelFixture', expected: 'future-issued stop reached an external-effect or uncertain boundary', pattern: /command\.Command == "llm_displacement_stop" && command\.IssuedAt\.After\(time\.Now\(\)\.UTC\(\)\)/, replacement: 'false' },
      { file: ownedStopLinuxPathSource, source: ownedStopLinuxSource, name: 'TestCheckpointFixedOwnedStopRemoteKernelFixture', expected: 'forged envelope caused signal/reap/terminal release/root acknowledgement', changes: [
        { pattern: /\|\| !wsproto\.VerifyCommand\(command, \[\]byte\(cfg\.CommandSigningSecret\)\)/, replacement: '|| false' },
        { pattern: /!bytes\.Equal\(pending\.OriginalEnvelope, request\.Command\)/, replacement: 'false' },
        { pattern: /!bytes\.Equal\(original, pending\.OriginalEnvelope\)/, replacement: 'false' },
        { pattern: /step\.EnvelopeSHA256 != sha256Hex\(request\.Command\)/, replacement: 'false' },
      ] },
    ];
    const mutations = ownedStopMode ? ownedStopMutations : reuseMode ? reuseMutations : controlledSourceMode ? (mode.includes('--faults') ? controlledSourceMutations : []) : lifecycleOnly ? lifecycleMutations : custodyMutations;
    for (let i = 0; i < mutations.length; i += 1) {
      const mutation = mutations[i];
      let altered = mutation.source;
      const changes = mutation.changes ?? [{ pattern: mutation.pattern, replacement: mutation.replacement }];
      for (const change of changes) {
        if (!change.pattern.test(altered)) throw new Error(`mutation target not found for ${mutation.name}`);
        altered = altered.replace(change.pattern, change.replacement);
      }
      const alteredPath = path.join(temp, `checkpoint_custody_mutation_${i}.go`);
      const overlayPath = path.join(temp, `checkpoint_custody_overlay_${i}.json`);
      const binaryPath = path.join(temp, `checkpoint_custody_mutant_${i}.test`);
      writeFileSync(alteredPath, altered, { mode: 0o600 });
      writeFileSync(overlayPath, JSON.stringify({ Replace: { [mutation.file]: alteredPath } }), { mode: 0o600 });
      run('go', ['test', '-c', '-overlay', overlayPath, '-o', binaryPath, './internal/nodeagent'], { env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64' } });
      mutationBinaries.push({ binary: linuxPath(binaryPath), local: binaryPath, test: mutation.name, expected: mutation.expected });
    }
  }

  // A bounded disposable proof filesystem is used for every gate invocation,
  // so G1 cannot pass without a real authenticated controlled-load receipt.
  // Exact external resources: one uniquely named 64 MiB image in a fresh
  // /tmp directory and one mountpoint; no existing filesystem/device is used.
  const commands = [
    'set -euo pipefail',
    `base=$(mktemp -d /tmp/checkpoint-custody-kernel.XXXXXX)`,
    'base_raw="$base"',
    'image="$base/verity.ext4"',
    'mnt="$base/mnt"',
    `cleanup(){ rc=$?; trap - EXIT HUP INT TERM; if mountpoint -q -- "$mnt"; then if ! timeout --signal=TERM --kill-after=2s 8s umount -- "$mnt"; then echo "unmount failed; preserving exact scratch directory: $base" >&2; exit 1; fi; fi; if mountpoint -q -- "$mnt"; then echo "mount remains active; preserving exact scratch directory: $base" >&2; exit 1; fi; ${Array.from({ length: mutationBinaries.length }, (_, i) => `if [[ -e "$base/mutant-${i}.log" ]]; then rm -f -- "$base/mutant-${i}.log"; fi;`).join(' ')} if [[ -e "$image" ]]; then rm -f -- "$image"; fi; if [[ -d "$mnt" ]]; then rmdir -- "$mnt"; fi; rmdir -- "$base"; exit "$rc"; }`,
    'trap cleanup EXIT HUP INT TERM',
    'base=$(realpath -e -- "$base")',
    '[[ "$base" == "$base_raw" ]]',
    '[[ "$base" =~ ^/tmp/checkpoint-custody-kernel\\.[[:alnum:]]+$ ]]',
    '[[ "$(realpath -m -- "$image")" == "$base/verity.ext4" ]]',
    '[[ "$(realpath -m -- "$mnt")" == "$base/mnt" ]]',
    'mkdir -- "$mnt"',
    'truncate -s 64M "$image"',
    '[[ -f "$image" && ! -L "$image" ]]',
    'timeout --signal=TERM --kill-after=2s 20s mkfs.ext4 -F -O verity -- "$image" >/dev/null',
    'timeout --signal=TERM --kill-after=2s 20s mount -o loop -- "$image" "$mnt"',
    'mountpoint -q -- "$mnt"',
    'CHECKPOINT_CUSTODY_VERITY_FILE="$mnt/model.bin"',
    'export CHECKPOINT_CUSTODY_VERITY_FILE',
    'printf "small fs-verity kernel fixture\\n" > "$CHECKPOINT_CUSTODY_VERITY_FILE"',
    'sync "$CHECKPOINT_CUSTODY_VERITY_FILE"',
    `export CHECKPOINT_CUSTODY_TEST_DIR="$mnt"`,
    `timeout --signal=TERM --kill-after=3s 55s "${linuxBin.replaceAll('"', '\\"')}" -test.timeout=45s -test.v -test.run=${quote(regex)}`,
    'echo __CHECKPOINT_CUSTODY_MAIN_TESTS_DONE__',
  ];
  for (let i = 0; i < mutationBinaries.length; i += 1) {
    const mutant = mutationBinaries[i];
    commands.push(`mkdir -- "$mnt/mutant-${i}"`);
    commands.push(`outputFile="$base/mutant-${i}.log"`);
    commands.push(`if CHECKPOINT_CUSTODY_TEST_DIR="$mnt/mutant-${i}" CHECKPOINT_CUSTODY_VERITY_FILE="$CHECKPOINT_CUSTODY_VERITY_FILE" timeout --signal=TERM --kill-after=3s 40s ${quote(mutant.binary)} -test.timeout=30s -test.v -test.run=${quote(`^${mutant.test}$`)} > "$outputFile" 2>&1; then echo "mutation survived: ${mutant.test}" >&2; cat "$outputFile" >&2; exit 1; fi`);
    commands.push(`grep -F -- ${quote(`--- FAIL: ${mutant.test}`)} "$outputFile" >/dev/null`);
    commands.push(`grep -F -- ${quote(mutant.expected)} "$outputFile" >/dev/null`);
    commands.push(`if grep -E 'panic:|no tests to run|build failed' "$outputFile" >/dev/null; then cat "$outputFile" >&2; exit 1; fi`);
    commands.push(`cat "$outputFile"`);
  }
  let output;
  if (mode.includes('--remote-proxmox')) {
    const runner = buildRemoteRunner({ selected, mutationBinaries });
    const payload = buildRemotePayload(binary, runner, mutationBinaries);
    const encodedReceiver = Buffer.from(remoteReceiverSource(), 'utf8').toString('base64');
    const pythonCommand = `exec(compile(__import__('base64').b64decode('${encodedReceiver}'), '<custody-transport>', 'exec'))`;
    const remoteCommand = `exec python3 -c ${quote(pythonCommand)}`;
    const key = 'C:/Users/Sasha/.ssh/cmp170_proxmox';
    const knownHosts = 'C:/Users/Sasha/.ssh/known_hosts';
    output = run('ssh', [
      '-T', '-i', key,
      '-o', 'BatchMode=yes',
      '-o', 'IdentitiesOnly=yes',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${knownHosts}`,
      '-o', 'ClearAllForwardings=yes',
      '-o', 'RequestTTY=no',
      '-o', 'ConnectTimeout=10',
      '-o', 'ServerAliveInterval=10',
      '-o', 'ServerAliveCountMax=3',
      'root@10.0.0.3', remoteCommand,
    ], { timeout: 1_100_000, maxBuffer: 32 * 1024 * 1024, input: payload });
    const cleanupMarker = '__CHECKPOINT_CUSTODY_REMOTE_CLEANUP_CONFIRMED__';
    if (!output.includes(cleanupMarker) || output.indexOf(cleanupMarker) !== output.lastIndexOf(cleanupMarker)) {
      throw new Error('remote custody cleanup confirmation is missing or ambiguous');
    }
    const mainMarker = '__CHECKPOINT_CUSTODY_MAIN_TESTS_DONE__';
    if (!output.includes(mainMarker)) throw new Error('custody main test completion marker is missing');
    if (ownedStopMode) assertOwnedStopRunInventory(output.split(mainMarker, 1)[0]);
    else if (reuseMode) assertReuseRunInventory(output.split(mainMarker, 1)[0]);
    else if (controlledSourceMode) assertControlledSourceRunInventory(output.split(mainMarker, 1)[0]);
    else assertTests(output.split(mainMarker, 1)[0], selected);
    if (lifecycleOnly) assertLifecycleScenarioCounters(output.split(mainMarker, 1)[0]);
    console.log(ownedStopMode ? 'checkpoint owned stop kernel verification passed' : reuseMode ? (mode.includes('--faults') ? 'checkpoint staging reuse fault verification passed' : 'checkpoint staging reuse verification passed') : controlledSourceMode ? (mode.includes('--faults') ? 'checkpoint controlled source fault verification passed' : 'checkpoint controlled source verification passed') : lifecycleOnly ? (mode.includes('--faults') ? 'checkpoint source lifecycle fault verification passed' : 'checkpoint source lifecycle verification passed') : kernelOnly ? 'checkpoint load custody kernel verification passed' : mode.includes('--faults') ? 'checkpoint load custody fault verification passed' : 'checkpoint load custody verification passed');
  } else {
    output = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', 'timeout', '--signal=TERM', '--kill-after=20s', '220s', 'bash', '--noprofile', '--norc', '-s'], { timeout: 240_000, input: `${commands.join('\n')}\n` });
  }
  if (!mode.includes('--remote-proxmox')) {
  const marker='__CHECKPOINT_CUSTODY_MAIN_TESTS_DONE__';if(!output.includes(marker))throw new Error('custody main test completion marker is missing');
  if (reuseMode) assertReuseRunInventory(output.split(marker, 1)[0]);
  else if (controlledSourceMode) assertControlledSourceRunInventory(output.split(marker, 1)[0]);
  else assertTests(output.split(marker,1)[0], selected);
  if (lifecycleOnly) assertLifecycleScenarioCounters(output.split(marker,1)[0]);
  console.log(reuseMode ? (mode.includes('--faults') ? 'checkpoint staging reuse fault verification passed' : 'checkpoint staging reuse verification passed') : controlledSourceMode ? (mode.includes('--faults') ? 'checkpoint controlled source fault verification passed' : 'checkpoint controlled source verification passed') : lifecycleOnly ? (mode.includes('--faults') ? 'checkpoint source lifecycle fault verification passed' : 'checkpoint source lifecycle verification passed') : kernelOnly ? 'checkpoint load custody kernel verification passed' : mode.includes('--faults') ? 'checkpoint load custody fault verification passed' : 'checkpoint load custody verification passed');
  }
} finally {
  rmSync(temp, { recursive: true, force: true });
}
