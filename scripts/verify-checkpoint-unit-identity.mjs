import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && !['--faults', '--bounds'].includes(args[0]))) {
  console.error('usage: node scripts/verify-checkpoint-unit-identity.mjs [--faults|--bounds]');
  process.exit(2);
}
const mode = args[0] ?? '';
const commonTests = [
  'TestCheckpointUnitIdentityParsesStrictSystemdProperties',
  'TestCheckpointUnitIdentityRequiresExactUnifiedCgroupMembership',
  'TestCheckpointUnitIdentityJoinsCustodyLocalIdentityAndStableUnit',
  'TestCheckpointUnitIdentityRejectsCustodyAliasAndProcessDrift',
  'TestCheckpointUnitIdentityRejectsChangingFreshSamples',
  'TestCheckpointUnitIdentityRejectsInactiveStableUnit',
  'TestCheckpointUnitIdentityRejectsIncompleteLocalPolicy',
  'TestCheckpointUnitIdentityValidatesPinnedIdentityRequest',
];
const linuxTests = [
  'TestCheckpointUnitIdentityLinuxSyntheticCollectorJoinsTwoFreshSamples',
  'TestCheckpointUnitIdentityLinuxSyntheticCollectorRejectsUnitDrift',
  'TestCheckpointUnitIdentityLinuxCgroupReaderIsNonblockingAndBounded',
  'TestCheckpointUnitIdentityLinuxHonorsCancellationAndCustodyFailure',
  'TestCheckpointUnitIdentityLinuxProcCgroupReadRejectsSymlink',
  'TestCheckpointUnitIdentityLinuxSystemdOutputWriterEnforcesByteCap',
  'TestCheckpointUnitIdentityLinuxRejectsNilAndCanceledContextBeforeCollection',
  'TestCheckpointUnitIdentityLinuxReverifiesCustodyAfterFinalSample',
  'TestCheckpointUnitIdentityLinuxExpiredCollectorDeadlineSkipsDownstream',
  'TestCheckpointUnitIdentityLinuxChecksContextAfterFinalCustodyVerification',
  'TestCheckpointUnitIdentityLinuxActualObserverRejectsDuplicateListeners',
];
const allTests = [...commonTests, ...linuxTests];
const declaredSource = readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_unit_identity_test.go'), 'utf8')
  + readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_unit_identity_linux_test.go'), 'utf8');
const declared = [...declaredSource.matchAll(/^func (TestCheckpointUnitIdentity\w+)\(/gm)].map((match) => match[1]);
for (const name of allTests) {
  if (!declared.includes(name)) throw new Error(`required feature test is missing: ${name}`);
}
const unexpected = declared.filter((name) => !allTests.includes(name));
if (unexpected.length) throw new Error(`unreviewed feature tests were added: ${unexpected.join(', ')}`);
if (new Set(declared).size !== declared.length || declared.length !== allTests.length) throw new Error('feature test inventory is duplicated or incomplete');

const env = {
  ...process.env,
  GOCACHE: path.join(repoRoot, '.unlazy/fleet-residency-v2/tmp/gocache-custody-current'),
};
function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: repoRoot, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (program === 'wsl.exe' && output.includes('E_ACCESSDENIED')) {
    throw new Error('WSL Linux artifact run denied by the sandbox (Wsl/Service/E_ACCESSDENIED); root execution is required. No retry or workaround was attempted.');
  }
  if (result.status !== 0) throw new Error(`${program} exited ${result.status ?? 'without a status'}\n${output}`);
  return output;
}
function runExpectedFailure(program, commandArgs, expectedTest, expectedMarker, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: repoRoot, env, encoding: 'utf8', timeout: 60_000, maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status !== 1 || result.signal != null) throw new Error(`${program} mutant did not fail with a normal test assertion (status=${result.status}, signal=${result.signal ?? 'none'})`);
  if (!output.includes(`--- FAIL: ${expectedTest}`) || !output.includes(expectedMarker) || /panic:|fatal error:|test timed out/i.test(output)) {
    throw new Error(`${program} mutant lacked its named fixture assertion or terminated abnormally\n${output}`);
  }
  return output;
}
function assertPassed(output, expected, label) {
  const passed = new Set();
  const skipped = new Set();
  for (const line of output.split(/\r?\n/)) {
    const text = line.trim();
    if (!text) continue;
    try {
      const event = JSON.parse(text);
      if (!event.Test) continue;
      if (event.Action === 'pass') passed.add(event.Test);
      if (event.Action === 'skip') skipped.add(event.Test);
    } catch {
      const pass = text.match(/^--- PASS: ([^\s(]+)/);
      const skip = text.match(/^--- SKIP: ([^\s(]+)/);
      if (pass) passed.add(pass[1]);
      if (skip) skipped.add(skip[1]);
    }
  }
  const missing = expected.filter((name) => !passed.has(name));
  if (missing.length || skipped.size) throw new Error(`${label} did not pass its exact required tests; absent=${missing.join(', ') || 'none'} skipped=${[...skipped].join(', ') || 'none'}`);
}
function runNativeTests(names) {
  const output = run('go', ['test', '-json', './internal/nodeagent', '-run', `^(${names.join('|')})$`, '-count=1', '-timeout=30s']);
  assertPassed(output, names, 'native feature suite');
}

const linuxHost = process.platform === 'linux';
const windowsHost = process.platform === 'win32';
if (!linuxHost && !windowsHost) throw new Error(`unsupported verification host: ${process.platform}`);
const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-unit-identity-'));
try {
  if (mode === '--bounds') {
    runNativeTests(linuxHost ? allTests : commonTests);
    if (windowsHost) await runWslTests(tempDir, linuxTests);
    const linuxSource = readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_unit_identity_linux.go'), 'utf8');
    const commonSource = readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_unit_identity.go'), 'utf8');
    for (const [description, condition] of [
      ['fixed absolute systemctl executable', linuxSource.includes('checkpointSystemctlPath = "/usr/bin/systemctl"')],
      ['no shell construction', !/exec\.Command(?:Context)?\([^\n]*\b(?:sh|bash|cmd\.exe)\b/.test(linuxSource)],
      ['no PATH or configuration override', !/"PATH=|SYSTEMD_UNIT_PATH|SYSTEMD_CONFIG|cmd\.Path\s*=|LookPath\(/.test(linuxSource)],
      ['bounded context', commonSource.includes('context.WithTimeout(ctx, 20*time.Second)') && linuxSource.includes('context.WithTimeout(ctx, 3*time.Second)')],
      ['bounded process wait', linuxSource.includes('cmd.WaitDelay = time.Second')],
      ['nonblocking no-follow cgroup reader', linuxSource.includes('unix.O_NOFOLLOW|unix.O_NONBLOCK')],
      ['bounded output and cgroup reads', linuxSource.includes('checkpointUnitMaxOutput') && linuxSource.includes('checkpointUnitMaxCgroupBytes+1')],
    ]) if (!condition) throw new Error(`bounds source assertion failed: ${description}`);
    console.log('checkpoint unit identity bounded verification passed');
  } else {
    runNativeTests(linuxHost ? allTests : commonTests);
    if (windowsHost) await runWslTests(tempDir, linuxTests);
    if (mode === '--faults') {
      runMutants(tempDir, linuxHost ? 'linux' : 'windows');
      console.log(`checkpoint unit identity fault verification passed; feature-tests=${allTests.length}; compiling-mutants=4`);
    } else {
      console.log(`checkpoint unit identity verification passed; feature-tests=${allTests.length}`);
    }
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}

async function runWslTests(dir, names) {
  const binaryPath = path.join(dir, 'nodeagent-linux.test');
  run('go', ['test', '-c', '-o', binaryPath, './internal/nodeagent'], {
    env: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
  });
  const linuxPath = windowsPathToWslPath(binaryPath);
  run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'chmod', '+x', linuxPath]);
  const output = run('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxPath, `-test.run=^(${names.join('|')})$`, '-test.count=1', '-test.timeout=30s', '-test.v']);
  assertPassed(output, names, 'WSL Linux feature suite');
}

function runMutants(dir, host) {
  const mutants = [
    {
      name: 'alias-guard', test: 'TestCheckpointUnitIdentityRejectsCustodyAliasAndProcessDrift', marker: 'accepted "wrong expected alias" drift',
      needle: 'binding.ActualAlias != expectedAlias', replacement: 'false && binding.ActualAlias != expectedAlias',
    },
    {
      name: 'stable-sample-guard', test: 'TestCheckpointUnitIdentityRejectsChangingFreshSamples', marker: 'accepted changing second unit sample',
      needle: 'first != second ||', replacement: 'false && first != second ||',
    },
    {
      name: 'active-state-guard', test: 'TestCheckpointUnitIdentityRejectsInactiveStableUnit', marker: 'accepted stable unit state "inactive"',
      needle: 'first.ActiveState != "active"', replacement: 'false && first.ActiveState != "active"',
    },
    {
      name: 'exact-cgroup-guard', test: 'TestCheckpointUnitIdentityRequiresExactUnifiedCgroupMembership', marker: 'accepted invalid cgroup membership fixture "prefix"',
      needle: 'found != expected', replacement: 'false && found != expected', source: 'internal/nodeagent/checkpoint_unit_identity.go',
    },
  ];
  for (const mutant of mutants) {
    const sourcePath = path.join(repoRoot, mutant.source ?? 'internal/nodeagent/checkpoint_unit_identity.go');
    const original = readFileSync(sourcePath, 'utf8');
    if (original.split(mutant.needle).length !== 2) throw new Error(`${mutant.name} mutation anchor was not unique`);
    const mutated = original.replace(mutant.needle, mutant.replacement);
    const replacementPath = path.join(dir, `${mutant.name}.go`);
    const overlayPath = path.join(dir, `${mutant.name}.overlay.json`);
    const binaryPath = path.join(dir, `${mutant.name}.test`);
    writeFileSync(replacementPath, mutated, 'utf8');
    writeFileSync(overlayPath, JSON.stringify({ Replace: { [sourcePath]: replacementPath } }), 'utf8');
    if (host === 'linux') {
      runExpectedFailure('go', ['test', `-overlay=${overlayPath}`, './internal/nodeagent', '-run', `^${mutant.test}$`, '-count=1', '-timeout=30s'], mutant.test, mutant.marker);
      continue;
    }
    run('go', ['test', '-c', `-overlay=${overlayPath}`, '-o', binaryPath, './internal/nodeagent'], {
      env: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
    });
    const linuxPath = windowsPathToWslPath(binaryPath);
    run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'chmod', '+x', linuxPath]);
    runExpectedFailure('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxPath, `-test.run=^${mutant.test}$`, '-test.count=1', '-test.timeout=30s', '-test.v'], mutant.test, mutant.marker);
  }
}

function windowsPathToWslPath(value) {
  const parsed = path.win32.parse(value);
  const drive = parsed.root.match(/^([A-Za-z]):\\$/)?.[1];
  if (!drive) throw new Error(`cannot map non-drive Windows path into the fixed Ubuntu WSL instance: ${value}`);
  const relative = value.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean);
  return `/mnt/${drive.toLowerCase()}/${relative.join('/')}`;
}
