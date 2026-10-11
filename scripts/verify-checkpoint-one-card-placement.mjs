import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const supplied = process.argv.slice(2);
if (supplied.length > 1 || (supplied.length === 1 && !['--faults', '--startup', '--regressions'].includes(supplied[0]))) {
  console.error('usage: node scripts/verify-checkpoint-one-card-placement.mjs [--faults|--startup|--regressions]');
  process.exit(2);
}
const mode = supplied[0] ?? '';
const ownedPaths = [
  'internal/nodeagent/checkpoint_launch_plan.go',
  'internal/nodeagent/checkpoint_launch_plan_test.go',
  'internal/nodeagent/checkpoint_launch_plan_linux_test.go',
  'scripts/verify-checkpoint-launch-plan.mjs',
  'internal/nodeagent/checkpoint_fixed_launcher.go',
  'internal/nodeagent/checkpoint_fixed_launcher_linux.go',
  'internal/nodeagent/checkpoint_fixed_launcher_test.go',
  'internal/nodeagent/checkpoint_fixed_launcher_linux_test.go',
  'scripts/verify-checkpoint-fixed-launcher.mjs',
  'internal/nodeagent/checkpoint_device_binding.go',
  'internal/nodeagent/checkpoint_device_binding_linux.go',
  'internal/nodeagent/checkpoint_device_binding_other.go',
  'internal/nodeagent/checkpoint_device_binding_test.go',
  'internal/nodeagent/checkpoint_device_binding_linux_test.go',
  'scripts/verify-checkpoint-one-card-placement.mjs',
];
const source = new Map(ownedPaths.map((file) => [file, readFileSync(path.join(root, file), 'utf8')]));
const [plan, launcher, linux, device, deviceLinux, tests] = [
  source.get(ownedPaths[0]), source.get(ownedPaths[4]), source.get(ownedPaths[5]),
  source.get(ownedPaths[9]), source.get(ownedPaths[10]), source.get(ownedPaths[12]),
];
const featureTests = [
  'TestCheckpointPlacementPlanBuildsOneDeviceInvocation',
  'TestCheckpointPlacementRejectsUnsupportedCeilingAndPartialFallback',
  'TestCheckpointPlacementRequiresFreshMatchingPhysicalIdentity',
  'TestCheckpointOffloadEvidenceRequiresActualAllLayerPlacement',
  'TestCheckpointOffloadLogRequiresOneCanonicalSummary',
  'TestCheckpointPlacementRuntimeVersionHasStrictBuildIdentity',
];
const linuxRouteTests = ['TestCheckpointChildPlacementNestedObserverAndNoFallback'];

function inventoryFailures(events, expectedNames) {
  const failures = [];
  const records = new Map(expectedNames.map((name) => [name, { runs: 0, terminal: [] }]));
  if (records.size !== expectedNames.length) failures.push('duplicate expected feature name');
  for (const event of events) {
    if (!event.Test || !['run', 'pass', 'skip', 'fail'].includes(event.Action)) continue;
    const record = records.get(event.Test);
    if (!record) { failures.push(`unexpected event ${event.Action} ${event.Test}`); continue; }
    if (event.Action === 'run') record.runs++;
    else record.terminal.push(event.Action);
    if (event.Action === 'skip') failures.push(`skip ${event.Test}`);
    if (event.Action === 'fail') failures.push(`fail ${event.Test}`);
  }
  for (const [name, record] of records) {
    if (record.runs !== 1) failures.push(`${name} ran ${record.runs} times`);
    if (record.terminal.length !== 1 || record.terminal[0] !== 'pass') failures.push(`${name} terminal events ${record.terminal.join(',')}`);
  }
  return failures;
}

function checkInventoryOracle() {
  const expected = ['positive'];
  const good = [{ Action: 'run', Test: 'positive' }, { Action: 'pass', Test: 'positive' }];
  const controls = [
    ['positive', good, false],
    ['missing', [], true],
    ['duplicate terminal', [...good, { Action: 'pass', Test: 'positive' }], true],
    ['skip', [{ Action: 'run', Test: 'positive' }, { Action: 'skip', Test: 'positive' }], true],
    ['unexpected', [...good, { Action: 'run', Test: 'unexpected' }], true],
  ];
  for (const [name, events, shouldFail] of controls) {
    if ((inventoryFailures(events, expected).length !== 0) !== shouldFail) throw new Error(`inventory oracle control failed: ${name}`);
  }
}

function assertSourceContract() {
  assert.match(plan, /checkpointLaunchPlanVersion2\s*=\s*"checkpoint-launch-plan-v2"/);
  assert.match(plan, /p\.MaxAccelerators != 1/);
  assert.match(plan, /legacy v1 plan cannot authorize managed placement/);
  assert.match(plan, /"--device", p\.Placement\.RuntimeDeviceToken, "--split-mode", "none", "--main-gpu", "0", "--n-gpu-layers", "all"/);
  assert.match(device, /CUDA_VISIBLE_DEVICES=/);
  assert.match(device, /partial CPU offload is unsupported until actual layer placement is independently observable/);
  assert.match(deviceLinux, /--query-gpu=uuid,pci\.bus_id/);
  assert.match(deviceLinux, /--query-compute-apps=pid,gpu_uuid,used_gpu_memory/);
  assert.match(deviceLinux, /checkpointNSGetNSTYPE/);
  assert.match(deviceLinux, /checkpointNSFSMagic/);
  assert.match(deviceLinux, /checkpointPIDNamespaceInitInode/);
  assert.match(deviceLinux, /runCheckpointGPUProcessInventory/);
  assert.match(deviceLinux, /observeCheckpointPIDNamespace\("\/proc\/self\/ns\/pid"\)/);
  assert.match(deviceLinux, /"ns\/pid"\)\)/);
  assert.match(deviceLinux, /validateCheckpointInitialPIDNamespace/);
  assert.match(deviceLinux, /namespaceRoute:\s*checkpointWorkerUsesNestedPIDNamespace/);
  assert.match(deviceLinux, /nestedAttribution:\s*observeCheckpointHostGPUAttribution/);
  assert.match(deviceLinux, /if nested \{[\s\S]*source\.nestedAttribution[\s\S]*return checkpointOffloadEvidence/);
  assert.match(deviceLinux, /source\.pidNamespace\(bounded, pid\)/);
  assert.match(device, /load_tensors: offloaded %d\/%d layers to GPU/);
assert.match(deviceLinux, /verifyCheckpointRuntimeHealth/);
assert.match(deviceLinux, /waitCheckpointRuntimeReady/);
assert.match(deviceLinux, /unix\.Preadv2[\s\S]*unix\.RWF_NOWAIT/);
assert.match(deviceLinux, /errCheckpointExecutableColdCache[\s\S]*errCheckpointExecutableNowaitUnsupported/);
assert.match(linux, /waitCheckpointRuntimeReady[\s\S]*joinFixedStartupTwice/);
assert.match(linux, /launch\.pidfd[\s\S]*unix\.Poll/);
  assert.match(plan, /commit 62acc89/);
  assert.doesNotMatch(`${device}\n${deviceLinux}`, /3080|3090|GeForce|RTX\s*\d{4}/i);
  assert.match(tests, /TestCheckpointPlacementRequiresFreshMatchingPhysicalIdentity/);
}

function run(program, args, expectedText) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 900_000, maxBuffer: 16 * 1024 * 1024, windowsHide: true });
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0 || !output.includes(expectedText)) {
    throw new Error(`${program} ${args.join(' ')} failed its bounded verifier (${result.status ?? 'unknown'})\n${output.slice(-6000)}`);
  }
  return output;
}

function runFeatureTests() {
  const sourcePaths = ['internal/nodeagent/checkpoint_device_binding_test.go'];
  const testSource = sourcePaths.map((file) => readFileSync(path.join(root, file), 'utf8')).join('\n');
  const declared = [...testSource.matchAll(/^func (TestCheckpoint(?:Placement|Offload)\w+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
  if (declared.length !== featureTests.length || new Set(declared).size !== declared.length || featureTests.some((name) => !declared.includes(name)) || declared.some((name) => !featureTests.includes(name))) {
    throw new Error(`exact one-card feature inventory mismatch: declared=${declared.join(',')}`);
  }
  if (/\bt\.Skip(?:f|Now)?\s*\(/.test(testSource)) throw new Error('one-card portable feature tests must not skip');
  const pattern = `^(${featureTests.join('|')})$`;
  const result = spawnSync('go', ['test', '-json', './internal/nodeagent', '-run', pattern, '-count=1', '-timeout=30s'], {
    cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
  });
  if (result.error) throw result.error;
  const events = [];
  const errors = [];
  for (const [index, line] of (result.stdout ?? '').split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try { events.push(JSON.parse(line)); } catch { errors.push(`malformed Go test event at line ${index + 1}`); }
  }
  errors.push(...inventoryFailures(events, featureTests));
  if (result.status !== 0) errors.push(`Go feature suite exited ${result.status ?? 'without status'}`);
  if (errors.length) throw new Error(`one-card exact feature inventory failed: ${[...new Set(errors)].join('; ')}`);
}

function runLinuxRouteFeatureTests() {
  const linuxSource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_device_binding_linux_test.go'), 'utf8');
  const declared = [...linuxSource.matchAll(/^func (TestCheckpointChildPlacement\w+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
  if (declared.length !== linuxRouteTests.length || new Set(declared).size !== declared.length || declared.some((name) => !linuxRouteTests.includes(name)) || linuxRouteTests.some((name) => !declared.includes(name))) {
    throw new Error(`nested one-card feature inventory mismatch: declared=${declared.join(',')}`);
  }
  if (/\bt\.Skip(?:f|Now)?\s*\(/.test(linuxSource)) throw new Error('Linux one-card feature tests must not skip');
  const pattern = `^(${linuxRouteTests.join('|')})$`;
  if (process.platform === 'linux') {
    const result = spawnSync('go', ['test', '-json', './internal/nodeagent', '-run', pattern, '-count=1', '-timeout=30s'], {
      cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    if (result.error) throw result.error;
    const events = [];
    const errors = [];
    for (const [index, line] of (result.stdout ?? '').split(/\r?\n/).entries()) {
      if (!line.trim()) continue;
      try { events.push(JSON.parse(line)); } catch { errors.push(`malformed Linux Go test event at line ${index + 1}`); }
    }
    errors.push(...inventoryFailures(events, linuxRouteTests));
    if (result.status !== 0) errors.push(`Linux one-card route suite exited ${result.status ?? 'without status'}`);
    if (errors.length) throw new Error(`Linux nested one-card inventory failed: ${[...new Set(errors)].join('; ')}`);
    return;
  }
  const temporary = mkdtempSync(path.join(tmpdir(), 'checkpoint-one-card-linux-'));
  try {
    const binary = path.join(temporary, 'nodeagent-linux.test');
    const compiled = spawnSync('go', ['test', '-c', '-o', binary, './internal/nodeagent'], {
      cwd: root, env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
      encoding: 'utf8', timeout: 120_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
    });
    if (compiled.error) throw compiled.error;
    if (compiled.status !== 0) throw new Error(`Linux route test cross-compile failed: ${(compiled.stderr ?? '').slice(-4000)}`);
    const parsed = path.win32.parse(binary);
    const drive = parsed.root.match(/^([A-Za-z]):\\$/)?.[1];
    if (!drive) throw new Error('Linux test binary cannot be mapped into fixed Ubuntu WSL');
    const linuxBinary = `/mnt/${drive.toLowerCase()}/${binary.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean).join('/')}`;
    const chmod = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--exec', 'chmod', '+x', linuxBinary], { cwd: root, encoding: 'utf8', timeout: 20_000, windowsHide: true });
    if (chmod.error) throw chmod.error;
    if (chmod.status !== 0) throw new Error(`Linux route test chmod failed: ${(chmod.stderr ?? '').slice(-2000)}`);
    const result = spawnSync('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxBinary, `-test.run=${pattern}`, '-test.count=1', '-test.timeout=30s', '-test.v'], { cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
    if (result.error) throw result.error;
    const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
    const events = [];
    for (const line of output.split(/\r?\n/)) {
      const value = line.trimStart();
      const run = /^=== RUN\s+(\S+)\s*$/.exec(value);
      const terminal = /^--- (PASS|SKIP|FAIL):\s+(\S+?)(?:\s+\([^)]*\))?\s*$/.exec(value);
      if (run) events.push({ Action: 'run', Test: run[1] });
      else if (terminal) events.push({ Action: terminal[1].toLowerCase(), Test: terminal[2] });
    }
    const failures = inventoryFailures(events, linuxRouteTests);
    if (result.status !== 0 || failures.length) throw new Error(`WSL nested one-card suite failed: ${failures.join('; ')}\n${output.slice(-5000)}`);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

function runPriorVerifiers() {
  const planModes = mode === '--faults' ? ['--faults'] : mode === '--startup' ? [] : mode === '--regressions' ? ['', '--faults', '--bounds'] : [''];
  const launcherModes = mode === '--faults' || mode === '--startup' ? ['--mode=faults'] : mode === '--regressions' ? ['--mode=default', '--mode=faults', '--mode=bounds'] : ['--mode=default'];
  for (const selector of planModes) {
    const args = ['scripts/verify-checkpoint-launch-plan.mjs', ...(selector ? [selector] : [])];
    run(process.execPath, args, selector === '--faults' ? 'checkpoint launch plan fault verification passed' : selector === '--bounds' ? 'checkpoint launch plan bounded verification passed' : 'checkpoint launch plan verification passed');
  }
  for (const selector of launcherModes) {
    run(process.execPath, ['scripts/verify-checkpoint-fixed-launcher.mjs', selector], `fixed checkpoint launcher ${selector.slice('--mode='.length)} verification passed`);
  }
}

checkInventoryOracle();
assertSourceContract();
runFeatureTests();
runLinuxRouteFeatureTests();
runPriorVerifiers();
const successToken = mode === '--faults'
  ? 'checkpoint one-card placement fault verification passed'
  : mode === '--startup'
    ? 'checkpoint one-card placement startup verification passed'
    : mode === '--regressions'
      ? 'checkpoint one-card placement regression verification passed'
      : 'checkpoint one-card placement verification passed';
console.log(`${successToken}; feature-tests=${featureTests.length}; prior-inventories=preserved`);
