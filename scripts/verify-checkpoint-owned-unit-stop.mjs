import { spawnSync } from 'node:child_process';
import { lstatSync, mkdtempSync, rmSync } from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv.slice(2);
const modes = new Set(['--mode=authority', '--mode=supervision', '--mode=unit-lifetime']);
if (mode.length !== 1 || !modes.has(mode[0])) {
  console.error('usage: node scripts/verify-checkpoint-owned-unit-stop.mjs --mode=authority|supervision|unit-lifetime');
  process.exit(2);
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 1_170_000, maxBuffer: 16 * 1024 * 1024, ...options });
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0) {
    process.stderr.write(output);
    throw new Error(`${program} exited ${result.status ?? 'without a status'}`);
  }
  return output;
}

function assertExactGoTestInventory(output, expected) {
  const runs = new Map(), passes = new Map(), failures = [], skips = [], malformed = [];
  for (const line of output.split(/\r?\n/)) {
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const match = line.match(/^\s*=== RUN\s+(\S+)\s*$/);
      if (!match) malformed.push(line); else runs.set(match[1], (runs.get(match[1]) ?? 0) + 1);
    }
    if (/^\s*--- (PASS|SKIP|FAIL):/.test(line)) {
      const match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
      if (!match) malformed.push(line);
      else if (match[1] === 'PASS') passes.set(match[2], (passes.get(match[2]) ?? 0) + 1);
      else if (match[1] === 'SKIP') skips.push(match[2]);
      else failures.push(match[2]);
    }
  }
  const unexpectedRuns = [...runs.keys()].filter((name) => !expected.includes(name));
  const unexpectedPasses = [...passes.keys()].filter((name) => !expected.includes(name));
  const missingRuns = expected.filter((name) => runs.get(name) !== 1);
  const missingPasses = expected.filter((name) => passes.get(name) !== 1);
  if (missingRuns.length || missingPasses.length || unexpectedRuns.length || unexpectedPasses.length || failures.length || skips.length || malformed.length) {
    throw new Error(`owned-stop exact test inventory mismatch: run-missing=${missingRuns}; pass-missing=${missingPasses}; unexpected-run=${unexpectedRuns}; unexpected-pass=${unexpectedPasses}; failures=${failures}; skips=${skips}; malformed=${malformed}`);
  }
}

function selfTestExactGoTestInventory() {
  const valid = '=== RUN   TestA\n--- PASS: TestA (0.00s)\n';
  assertExactGoTestInventory(valid, ['TestA']);
  const rejected = [
    ['missing run', '--- PASS: TestA (0.00s)\n'],
    ['duplicate run', '=== RUN TestA\n=== RUN TestA\n--- PASS: TestA (0.00s)\n'],
    ['missing pass', '=== RUN TestA\n'],
    ['duplicate pass', '=== RUN TestA\n--- PASS: TestA (0.00s)\n--- PASS: TestA (0.00s)\n'],
    ['skipped test', '=== RUN TestA\n--- SKIP: TestA (0.00s)\n'],
    ['failed test', '=== RUN TestA\n--- FAIL: TestA (0.00s)\n'],
    ['unexpected test', '=== RUN TestA\n=== RUN TestB\n--- PASS: TestA (0.00s)\n--- PASS: TestB (0.00s)\n'],
    ['malformed event', '=== RUN\n--- PASS: TestA\n'],
  ];
  for (const [label, output] of rejected) {
    let threw = false;
    try { assertExactGoTestInventory(output, ['TestA']); } catch { threw = true; }
    if (!threw) throw new Error(`test-inventory parser accepted its ${label} negative control`);
  }
}
selfTestExactGoTestInventory();

function wslRepoPath() {
  const converted = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', 'wslpath', '-a', root]).trim();
  if (!converted.startsWith('/') || converted.includes('\n') || converted.includes('\r')) throw new Error('workspace did not map to one canonical local WSL path');
  return converted;
}

function wslPathForLocal(localPath) {
  const converted = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', 'wslpath', '-a', localPath]).trim();
  if (!converted.startsWith('/') || converted.includes('\n') || converted.includes('\r')) throw new Error('private test binary did not map to one canonical WSL path');
  return converted;
}

function withLinuxTestBinary(tags, testArgs, packagePath = './internal/nodeagent', binaryName = 'linux.test') {
  const temp = mkdtempSync(path.join(root, '.tmp-owned-stop-verifier-'));
  const before = lstatSync(temp);
  const binary = path.join(temp, binaryName);
  try {
    run('go', ['test', '-c', ...(tags ? ['-tags', tags] : []), '-o', binary, packagePath], {
      env: { ...process.env, CGO_ENABLED: '0', GOOS: 'linux', GOARCH: 'amd64', GOENV: 'off', GOFLAGS: '', GOTOOLCHAIN: 'local' },
    });
    const repo = wslRepoPath();
    const linuxBinary = wslPathForLocal(binary);
    const regex = testArgs.run;
    const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;
    const selectedEnv = (testArgs.env ?? []).map(shellQuote).join(' ');
    const shell = `cd -- ${shellQuote(repo)} && timeout --signal=TERM --kill-after=10s ${testArgs.timeout} env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C ${selectedEnv} ${shellQuote(linuxBinary)} -test.v -test.count=1 -test.timeout=${testArgs.testTimeout} -test.run=${shellQuote(regex)}`;
    const output = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--', 'bash', '--noprofile', '--norc', '-lc', shell], { timeout: testArgs.hostTimeout, maxBuffer: 16 * 1024 * 1024 });
    return output;
  } finally {
    const current = lstatSync(temp);
    if (path.dirname(temp) !== root || !path.basename(temp).startsWith('.tmp-owned-stop-verifier-') || !current.isDirectory() || current.dev !== before.dev || current.ino !== before.ino) {
      throw new Error('private cross-compiled verifier directory identity changed; preserved it');
    }
    rmSync(temp, { recursive: true, force: true });
  }
}

try {
  if (mode[0] === '--mode=authority') {
    const protocolTests = [
      'TestOwnedStopWireSchemaAndOriginalEnvelope',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/noncanonical_target',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/unknown_admin_argument',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/wrong_step',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/nonpositive_fence',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/uppercase_binding_digest',
      'TestOwnedStopWireSchemaAndOriginalEnvelope/unsafe_snapshot',
    ];
    const selected = [
      'TestOwnedStopAcceleratorWideFenceAndOperationLedger',
      'TestOwnedStopHandlePersistsSignedOriginalBeforeIPC',
      'TestOwnedStopHandleDirectVictimUrgentSameProcess',
      'TestOwnedStopReceiptRequiresRootSignatureAndExactIntentJoin',
      'TestOwnedStopReceiptRequiresRootSignatureAndExactIntentJoin/wrong_target',
      'TestOwnedStopReceiptRequiresRootSignatureAndExactIntentJoin/release_not_proven',
      'TestOwnedStopReceiptRequiresRootSignatureAndExactIntentJoin/signal_not_proven',
      'TestJournalMismatchCannotBeDowngradedByPersistedWarmBlock',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/wrong_ExitType',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/wrong_MainPID',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/wrong_worker_incarnation',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/wrong_supervisor_incarnation',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/early_supervisor_death',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/supervisor_escaped_unit',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/worker_did_not_exit',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/missing_durable_acknowledgement',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/unit_exited_before_acknowledgement',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/unit_remained_active',
      'TestCheckpointOwnedStopLifetimeVerifierRejectsFalseCredit/invalid_cgroup',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup/node-owned_public_key',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup/wrong_public_group',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup/writable_public_key',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup/linked_public_key',
      'TestOwnedStopPublicKeyCannotBeNodeOwnedOrWrongGroup/truncated_public_key',
      'TestOwnedStopSupervisorSuccessRequiresDurableAcknowledgement',
    ];
    const regex = `^(${selected.join('|')})$`;
    const protocolRegex = `^(${protocolTests.join('|')})$`;
    const protocolOutput = withLinuxTestBinary('', { run: protocolRegex, timeout: '90s', testTimeout: '80s', hostTimeout: 120_000 }, './internal/wsproto', 'wsproto-linux.test');
    assertExactGoTestInventory(protocolOutput, protocolTests);
    const output = withLinuxTestBinary('', { run: regex, timeout: '180s', testTimeout: '170s', hostTimeout: 210_000, env: ['VRAM_GOVERNOR_OWNED_STOP_G1_FIXTURE=1'] });
    assertExactGoTestInventory(output, selected);
    if (output.split('__OWNED_STOP_G1_FIXTURE_POSITIVE__').length !== 2) throw new Error('owned-stop G1 durable IPC fixture lacks exactly one positive marker');
    if (output.split('__OWNED_STOP_G1_DIRECT_VICTIM_URGENT__').length !== 2) throw new Error('owned-stop direct same-process victim/urgent fixture lacks exactly one positive marker');
    console.log('checkpoint owned unit stop authority verification passed');
  } else if (mode[0] === '--mode=supervision') {
    const output = run(process.execPath, [path.join(root, 'scripts/verify-checkpoint-load-custody.mjs'), '--owned-stop', '--remote-proxmox', '--faults']);
    if (!output.includes('checkpoint owned stop kernel verification passed')) throw new Error('owned-stop remote kernel verifier summary is absent');
    process.stdout.write(output);
    console.log('checkpoint owned unit stop supervision verification passed');
  } else {
    const output = withLinuxTestBinary('owned_stop_systemd_lifetime', { run: '^TestOwnedStopSystemdLifetimeVerifier$', timeout: '150s', testTimeout: '130s', hostTimeout: 210_000 });
    assertExactGoTestInventory(output, ['TestOwnedStopSystemdLifetimeVerifier']);
    console.log('checkpoint owned unit stop lifetime verification passed');
  }
} catch (error) {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
}
