import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const root = process.cwd();
const paths = {
  generic: 'internal/nodeagent/checkpoint_fixed_launcher.go',
  linux: 'internal/nodeagent/checkpoint_fixed_launcher_linux.go',
  other: 'internal/nodeagent/checkpoint_fixed_launcher_other.go',
  genericTests: 'internal/nodeagent/checkpoint_fixed_launcher_test.go',
  linuxTests: 'internal/nodeagent/checkpoint_fixed_launcher_linux_test.go',
  command: 'cmd/checkpoint-fixed-launcher/main.go',
  unit: 'deploy/llama-server.service',
  placementGeneric: 'internal/nodeagent/checkpoint_device_binding.go',
  placementLinux: 'internal/nodeagent/checkpoint_device_binding_linux.go',
  placementLinuxTests: 'internal/nodeagent/checkpoint_device_binding_linux_test.go',
};
const source = Object.fromEntries(Object.entries(paths).map(([name, path]) => [name, readFileSync(join(root, path), 'utf8')]));

const modeArg = process.argv.slice(2);
if (modeArg.length > 1 || (modeArg.length === 1 && !['--mode=source', '--mode=default', '--mode=faults', '--mode=bounds'].includes(modeArg[0]))) {
  throw new Error('usage: node scripts/verify-checkpoint-fixed-launcher.mjs [--mode=source|default|faults|bounds]');
}
const mode = modeArg[0]?.slice('--mode='.length) ?? 'default';
const genericTests = [
  { test: 'TestCheckpointFixedLauncherUsesFixedInvocation' },
  { test: 'TestCheckpointFixedLauncherRejectsMissingContext' },
  { test: 'TestCheckpointFixedLauncherDoesNotAcceptCallerCommand' },
  { test: 'TestCheckpointFixedLauncherStartupJoinRequiresTwoStableAssociations', subtests: [
    'supervisor main pid', 'non activating', 'wrong invocation', 'wrong cgroup', 'wrong parent',
    'missing supervisor incarnation', 'wrong alias', 'wrong receipt model', 'wrong process incarnation', 'wrong sole listener',
    'forged staged executable', 'wrong physical GPU', 'missing full layer evidence',
    'first sample gpu below bound', 'second sample host above bound',
  ] },
  { test: 'TestCheckpointFixedLauncherRuntimeOptionsCommand' },
  { test: 'TestCheckpointLaunchPlanRuntimeOptionsSpecCopy' },
];
const linuxTests = [
  { test: 'TestCheckpointFixedLauncherLinuxParsersFailClosed' },
  { test: 'TestCheckpointFixedLauncherLinuxNotifyBarrierSCMRights' },
  { test: 'TestCheckpointFixedLauncherLinuxNotifyBarrierRejectsUnexpectedData' },
  { test: 'TestCheckpointFixedLauncherLinuxNotifyBarrierHonorsCancellation' },
  { test: 'TestCheckpointFixedLauncherLinuxNotifySendHonorsFullQueueAndRecovers' },
  { test: 'TestCheckpointDeviceBindingRuntimeListingIsUniqueUnderMask' },
  { test: 'TestCheckpointDeviceBindingGPUProcessInventoryIsStrict' },
  { test: 'TestCheckpointDeviceBindingPIDNamespaceIsFailClosed' },
  { test: 'TestCheckpointDeviceBindingChildPlacementObservationBoundedJoin', subtests: [
    'missing gpu attribution', 'extra gpu attribution', 'wrong physical gpu',
    'unanchored pid namespace', 'malformed gpu inventory', 'missing full offload evidence',
    'changed child incarnation', 'before ready abort retains ownership',
  ] },
  { test: 'TestCheckpointRuntimeReadinessLoadingThenReadyAndFailures', subtests: [
    'loading then ready', 'forever loading deadline', 'malformed loading', 'fatal error',
    'wrong endpoint status', 'ready duplicate key', 'loading duplicate key', 'ready casefold field',
    'ready mixed alias', 'loading casefold root', 'loading casefold nested', 'loading mixed nested alias',
    'trailing data', 'canceled or dead child',
  ] },
  { test: 'TestCheckpointExecutableHashUsesBoundedNonblockingHeldFD' },
];

function exactFunctionInventory(text, expected, label) {
  assert.deepEqual(functionInventoryFailures(text, expected), [], `${label} test inventory has missing, duplicate, or unexpected cases`);
  assert.doesNotMatch(text, /\bt\.Skip(?:f|Now)?\s*\(/, `${label} tests must not skip`);
}
function functionInventoryFailures(text, expected) {
  const found = [...text.matchAll(/^func (TestCheckpoint(?:FixedLauncher|LaunchPlan|DeviceBinding|Runtime|ExecutableHash)\w+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
  const expectedNames = expected.map((item) => item.test);
  const names = new Set([...found, ...expectedNames]);
  const failures = [];
  for (const name of names) {
    const count = found.filter((item) => item === name).length;
    const expectedCount = expectedNames.filter((item) => item === name).length;
    if (expectedCount !== 1 || count !== 1) failures.push(`${name} found ${count}, expected ${expectedCount}`);
  }
  return failures.sort();
}
exactFunctionInventory(source.genericTests, genericTests, 'portable');
exactFunctionInventory(`${source.linuxTests}\n${source.placementLinuxTests}`, linuxTests, 'Linux');
function startupSubtestInventoryFailures(text, expected) {
  const found = [...text.matchAll(/^\s*"([^"]+)":\s*func\(s \*checkpointFixedStartupSample\)/gm)].map((match) => match[1]);
  const names = new Set([...found, ...expected]);
  return [...names].filter((name) => expected.filter((value) => value === name).length !== 1 || found.filter((value) => value === name).length !== 1).sort();
}
assert.deepEqual(startupSubtestInventoryFailures(source.genericTests, genericTests[3].subtests), [], 'startup fault subtest inventory has missing, duplicate, or unexpected cases');

function goTestFunctionSpan(text, name) {
  const declaration = `func ${name}(t *testing.T) {`;
  const start = text.indexOf(declaration);
  if (start < 0 || text.slice(text.lastIndexOf('\n', start) + 1, start).trim() !== '') return null;
  const next = text.slice(start + declaration.length).search(/^func /m);
  const end = next < 0 ? text.length : start + declaration.length + next;
  return { start, end, body: text.slice(start, end) };
}

function sourceChildInventoryFailures(text, feature) {
  const span = goTestFunctionSpan(text, feature.test);
  if (!span) return [`missing function ${feature.test}`];
  const found = [
    ...span.body.matchAll(/^\s*"([^"]+)":\s*func\(s \*checkpointFixedStartupSample\)/gm),
    ...span.body.matchAll(/^\s*\{"([^"]+)"\s*,/gm),
    ...span.body.matchAll(/t\.Run\("([^"]+)"/g),
  ].map((match) => match[1]);
  const expected = feature.subtests ?? [];
  const names = new Set([...found, ...expected]);
  return [...names].filter((name) => expected.filter((value) => value === name).length !== 1 || found.filter((value) => value === name).length !== 1)
    .map((name) => `${feature.test}/${name} source count mismatch`).sort();
}

assert.match(source.generic, /checkpointFixedPlanPath\s*=\s*"\/etc\/vram-governor\/llama-server-plan\.json"/, 'canonical plan path is not fixed');
assert.match(source.generic, /checkpointFixedCustodyRoot\s*=\s*"\/var\/lib\/vram-governor\/checkpoint-custody"/, 'custody root must match the service writable path');
assert.match(source.generic, /checkpointFixedSnapshotRoot\s*=\s*"\/var\/lib\/vram-governor\/checkpoint-snapshots"/, 'snapshot root must match the service writable path');
for (const [needle, label] of [['Type=notify', 'notify service type'], ['NotifyAccess=all', 'all-cgroup notifier access'], ['KillMode=control-group', 'whole-cgroup lifetime']]) assert.ok(source.unit.includes(needle), `missing ${label}`);
assert.match(source.linux, /MAINPID="\+strconv\.Itoa\(pid\)/, 'MAINPID must be sent alone');
assert.match(source.linux, /n\.send\(ctx, "BARRIER=1", pipe\[1\]\)/, 'barrier must carry exactly the private pipe writer');
assert.match(source.linux, /runCheckpointFixedCommitAfterReadiness[\s\S]*waitCheckpointRuntimeReady[\s\S]*launch\.Commit/, 'production custody commit must wait for pinned loading-state readiness');
assert.match(source.linux, /steps := checkpointFixedStartupSteps\{[\s\S]*commit: func\(stepCtx context\.Context\) error[\s\S]*launch\.Commit[\s\S]*mainPID: func\(stepCtx context\.Context, workerPID int\) error[\s\S]*notify\.MainPID\(callCtx, workerPID\)[\s\S]*barrier: func\(stepCtx context\.Context\) error[\s\S]*notify\.Barrier\)[\s\S]*joinFixedStartupTwice[\s\S]*ready: func\(stepCtx context\.Context\) error[\s\S]*notify\.Ready[\s\S]*runCheckpointFixedStartupSteps\(bounded, pid, steps\)/, 'existing commit, MAINPID, barrier, local joins, READY protocol must remain ordered');
assert.match(source.linux, /ActiveState=active[\s\S]*SubState=running/, 'the public unit state parser must remain active-only');
assert.match(source.other, /requires supported Linux systemd, pidfd, fs-verity, and cgroup facilities/, 'unsupported platforms must fail closed');
assert.match(source.command, /len\(os\.Args\) != 1/, 'launcher command must reject caller arguments');
assert.doesNotMatch(source.linux, /--gpu-layers|--split-mode|--main-gpu|--device(?:=|\s)/i, 'launcher must not add accelerator placement argv');
assert.match(source.generic, /cmd\.Env\s*=\s*\[\]string\{[^}]*\}/, 'worker environment must be an explicit allowlist');
assert.doesNotMatch(source.generic.match(/cmd\.Env\s*=\s*\[\]string\{([^}]*)\}/)?.[1] ?? '', /NOTIFY_SOCKET/, 'worker must not inherit the manager notification socket');
assert.match(source.placementGeneric, /CUDA_VISIBLE_DEVICES=/, 'selected device must be scoped to the child environment');
assert.match(source.generic, /fixedCheckpointPlacementCommand/, 'placement command must be locally constructed');
assert.match(source.placementLinux, /--query-gpu=uuid,pci\.bus_id/, 'CUDA adapter must obtain independent UUID/PCI inventory');
assert.match(source.placementLinux, /--query-compute-apps=pid,gpu_uuid,used_gpu_memory/, 'startup must independently attribute every child GPU row');
assert.match(source.placementLinux, /checkpointNSGetNSTYPE/, 'startup must verify the initial PID namespace through NS_GET_NSTYPE');
assert.match(source.placementLinux, /checkpointPIDNamespaceInitInode/, 'startup must verify the reserved initial PID namespace inode');
assert.match(source.placementLinux, /runCheckpointGPUProcessInventory/, 'startup must verify the CUDA inventory subprocess PID namespace');
assert.match(source.placementLinux, /observeCheckpointPIDNamespace\("\/proc\/self\/ns\/pid"\)/, 'startup must anchor the NVML query observer namespace');
assert.match(source.placementLinux, /"ns\/pid"\)\)/, 'startup must anchor the managed worker namespace');
assert.match(source.placementLinux, /verifyCheckpointRuntimeHealth/, 'offload summary must be followed by current runtime health');
assert.match(source.placementLinux, /rejectCheckpointHealthJSONKeys\(body[\s\S]*decoder := json\.NewDecoder/, 'health envelopes must reject noncanonical keys before typed decoding');
assert.match(source.placementLinux, /root = map\[string\]struct\{\}\{"error": \{\}\}[\s\S]*"\$\.error"\].*"code".*"message".*"type"/, 'loading health schema must require exact nested error keys');
assert.match(source.placementLinux, /Loading model[\s\S]*unavailable_error[\s\S]*waitCheckpointRuntimeReady/, 'only the pinned runtime loading response may be retried');
assert.match(source.placementLinux, /unix\.Preadv2[\s\S]*unix\.RWF_NOWAIT/, 'executable hashing must use nonwaiting data reads');
assert.match(source.placementLinux, /errCheckpointExecutableColdCache[\s\S]*errCheckpointExecutableNowaitUnsupported/, 'cold/unsupported filesystems must fail closed');
assert.match(source.linux, /launch\.pidfd[\s\S]*unix\.Poll/, 'loading retry must retain and poll current child pidfd');
assert.doesNotMatch(source.placementLinux, /3080|3090|GeForce|product name/i, 'placement must not schedule by GPU product name');

function inventoryFailures(events, features) {
  const failures = [];
  const expected = new Map();
  for (const feature of features) {
    for (const name of [feature.test, ...(feature.subtests ?? []).map((subtest) => `${feature.test}/${subtest.replaceAll(' ', '_')}`)]) {
      if (expected.has(name)) failures.push(`duplicate expected path ${name}`);
      expected.set(name, { runs: 0, terminal: [] });
    }
  }
  for (const event of events.filter((item) => item.Test && ['run', 'pass', 'skip', 'fail'].includes(item.Action))) {
    const record = expected.get(event.Test);
    if (!record) { failures.push(`unexpected event ${event.Action} ${event.Test}`); continue; }
    if (event.Action === 'run') record.runs++;
    else record.terminal.push(event.Action);
    if (event.Action === 'skip') failures.push(`skip ${event.Test}`);
    if (event.Action === 'fail') failures.push(`fail ${event.Test}`);
  }
  for (const [name, record] of expected) {
    if (record.runs !== 1) failures.push(`${name} ran ${record.runs} times`);
    if (record.terminal.length !== 1 || record.terminal[0] !== 'pass') failures.push(`${name} terminal events ${record.terminal.join(',')}`);
  }
  return failures;
}

function selfCheckInventoryOracle() {
  const expected = [{ test: 'TestPositive', subtests: ['control'] }];
  const good = [
    { Action: 'run', Test: 'TestPositive' }, { Action: 'run', Test: 'TestPositive/control' },
    { Action: 'pass', Test: 'TestPositive/control' }, { Action: 'pass', Test: 'TestPositive' },
  ];
  const faults = [
    ['positive', good, false],
    ['missing', good.slice(0, 2), true],
    ['duplicate', [...good, { Action: 'pass', Test: 'TestPositive/control' }], true],
    ['skip', good.map((e) => e.Test === 'TestPositive/control' && e.Action === 'pass' ? { ...e, Action: 'skip' } : e), true],
    ['unexpected', [...good, { Action: 'run', Test: 'TestPositive/unexpected' }], true],
  ];
  for (const [name, events, expectedFailure] of faults) {
    if ((inventoryFailures(events, expected).length > 0) !== expectedFailure) throw new Error(`inventory oracle control failed: ${name}`);
  }
  const realistic = parseVerboseEvents([
    '=== RUN   TestPositive',
    '=== RUN   TestPositive/control',
    '    --- PASS: TestPositive/control (0.00s)',
    '--- PASS: TestPositive (0.00s)',
  ].join('\n'));
  if (inventoryFailures(realistic, expected).length) throw new Error('verbose event parser rejected Go subtest output with indentation');
  const malformed = [
    ['missing', '=== RUN   TestPositive\n--- PASS: TestPositive (0.00s)'],
    ['duplicate', '=== RUN   TestPositive\n=== RUN   TestPositive/control\n    --- PASS: TestPositive/control (0.00s)\n    --- PASS: TestPositive/control (0.00s)\n--- PASS: TestPositive (0.00s)'],
    ['skip', '=== RUN   TestPositive\n=== RUN   TestPositive/control\n    --- SKIP: TestPositive/control (0.00s)\n--- PASS: TestPositive (0.00s)'],
    ['fail', '=== RUN   TestPositive\n=== RUN   TestPositive/control\n    --- FAIL: TestPositive/control (0.00s)\n--- FAIL: TestPositive (0.00s)'],
    ['unexpected', '=== RUN   TestPositive\n=== RUN   TestPositive/control\n    --- PASS: TestPositive/control (0.00s)\n=== RUN   TestPositive/unexpected\n--- PASS: TestPositive/unexpected (0.00s)\n--- PASS: TestPositive (0.00s)'],
  ];
  for (const [name, transcript] of malformed) {
    if (!inventoryFailures(parseVerboseEvents(transcript), expected).length) throw new Error(`verbose parser control accepted ${name} event`);
  }
}

function syntheticGoEvents(features) {
  const events = [];
  for (const feature of features) {
    events.push({ Action: 'run', Test: feature.test });
    for (const subtest of feature.subtests ?? []) events.push({ Action: 'run', Test: `${feature.test}/${subtest.replaceAll(' ', '_')}` });
  }
  for (const feature of features) {
    for (const subtest of feature.subtests ?? []) events.push({ Action: 'pass', Test: `${feature.test}/${subtest.replaceAll(' ', '_')}` });
    events.push({ Action: 'pass', Test: feature.test });
  }
  return events;
}

function appendToFunction(text, name, statement) {
  const span = goTestFunctionSpan(text, name);
  if (!span) throw new Error(`source mutant anchor missing for ${name}`);
  const close = text.lastIndexOf('\n}', span.end);
  if (close < span.start) throw new Error(`source mutant closing brace missing for ${name}`);
  return text.slice(0, close) + `\n\t${statement}` + text.slice(close);
}

function sourceInventoryControls() {
  const features = [...genericTests, ...linuxTests];
  const childCount = features.reduce((sum, feature) => sum + (feature.subtests?.length ?? 0), 0);
  assert.equal(features.length, 17, 'fixed-launcher source inventory must retain all 17 top-level tests');
  assert.equal(childCount, 37, 'fixed-launcher source inventory must retain all 37 named children');
  assert.equal(features.length + childCount, 54, 'fixed-launcher source inventory must contain exactly 54 test occurrences');
  const verifierText = readFileSync(join(root, 'scripts/verify-checkpoint-fixed-launcher.mjs'), 'utf8');
  const sourceBranchStart = [...verifierText.matchAll(/^if \(mode === 'source'\) \{$/gm)].at(-1)?.index ?? -1;
  const sourceBranchEnd = verifierText.indexOf('\n} else {', sourceBranchStart);
  const firstRuntimeCall = Math.min(...['runWindowsGoTests(windowsFeatures);', 'runLinuxFixture(linuxFeatures);', 'verifyNativeCommandBuild();']
    .map((call) => verifierText.indexOf(call, sourceBranchEnd)).filter((index) => index >= 0));
  const sourceBranch = sourceBranchStart >= 0 && sourceBranchEnd > sourceBranchStart ? verifierText.slice(sourceBranchStart, sourceBranchEnd) : '';
  assert.ok(sourceBranch && sourceBranchEnd < firstRuntimeCall && sourceBranch.includes('sourceInventoryControls();') &&
    !/mkdtempSync|spawnSync|runWindowsGoTests|runLinuxFixture|verifyNativeCommandBuild/.test(sourceBranch),
  'source mode must complete pure inventory checks before any temp/compiler/WSL runner call');
  assert.ok(verifierText.includes("const windowsFeatures = mode === 'faults' ? [genericTests[3]] : genericTests;") &&
    verifierText.includes('runWindowsGoTests(windowsFeatures);') &&
    genericTests.some((feature) => feature.test === 'TestCheckpointFixedLauncherRuntimeOptionsCommand') &&
    genericTests.some((feature) => feature.test === 'TestCheckpointLaunchPlanRuntimeOptionsSpecCopy'),
  'default/bounds actual invocation must pass both new generic tests through the strict event inventory');

  const childSources = [
    [source.genericTests, genericTests],
    [source.linuxTests, linuxTests.filter((feature) => feature.test.startsWith('TestCheckpointFixedLauncherLinux'))],
    [source.placementLinuxTests, linuxTests.filter((feature) => !feature.test.startsWith('TestCheckpointFixedLauncherLinux'))],
  ];
  const childSourceFailures = childSources.flatMap(([text, ownedFeatures]) =>
    ownedFeatures.filter((feature) => feature.subtests?.length).flatMap((feature) => sourceChildInventoryFailures(text, feature)));
  assert.deepEqual(childSourceFailures, [], 'all expected named children must occur exactly once in their Go test bodies');

  const runtimeOptionsDecl = 'func TestCheckpointFixedLauncherRuntimeOptionsCommand(t *testing.T) {';
  assert.deepEqual(functionInventoryFailures(source.genericTests, genericTests), [], 'portable source positive inventory failed');
  assert.ok(functionInventoryFailures(source.genericTests.replace(runtimeOptionsDecl, ''), genericTests).length > 0,
    'missing top-level source mutant was accepted');
  assert.ok(functionInventoryFailures(`${source.genericTests}\n${runtimeOptionsDecl}`, genericTests).length > 0,
    'duplicate top-level source mutant was accepted');
  assert.ok(functionInventoryFailures(`${source.genericTests}\nfunc TestCheckpointFixedLauncherUnexpected(t *testing.T) {}`, genericTests).length > 0,
    'extra top-level source mutant was accepted');

  const startupChild = genericTests[3].subtests[0];
  const startupChildLine = source.genericTests.split(/\r?\n/).find((line) => line.includes(`"${startupChild}"`) && line.includes('func(s *checkpointFixedStartupSample)'));
  assert.ok(startupChildLine, 'startup child source mutant anchor missing');
  assert.ok(startupSubtestInventoryFailures(source.genericTests.replace(startupChildLine, ''), genericTests[3].subtests).length > 0,
    'missing child source mutant was accepted');
  assert.ok(startupSubtestInventoryFailures(`${source.genericTests}\n${startupChildLine}`, genericTests[3].subtests).length > 0,
    'duplicate child source mutant was accepted');
  assert.ok(startupSubtestInventoryFailures(`${source.genericTests}\n\t\t"unexpected source child": func(s *checkpointFixedStartupSample) {}`, genericTests[3].subtests).length > 0,
    'extra child source mutant was accepted');

  const readinessFeature = linuxTests.find((feature) => feature.test === 'TestCheckpointRuntimeReadinessLoadingThenReadyAndFailures');
  const readinessSource = source.placementLinuxTests;
  const readinessLabel = 'loading then ready';
  assert.ok(sourceChildInventoryFailures(readinessSource.replace(`t.Run("${readinessLabel}",`, 't.Run("removed child",'), readinessFeature).length > 0,
    'missing Linux child source mutant was accepted');
  assert.ok(sourceChildInventoryFailures(appendToFunction(readinessSource, readinessFeature.test, `t.Run("${readinessLabel}", func(t *testing.T) {})`), readinessFeature).length > 0,
    'duplicate Linux child source mutant was accepted');
  assert.ok(sourceChildInventoryFailures(appendToFunction(readinessSource, readinessFeature.test, 't.Run("unexpected source child", func(t *testing.T) {})'), readinessFeature).length > 0,
    'extra Linux child source mutant was accepted');

  const expectedEvents = eventFeatures(features);
  const goodEvents = syntheticGoEvents(expectedEvents);
  assert.deepEqual(inventoryFailures(goodEvents, expectedEvents), [], '54-occurrence source inventory positive control failed');
  const requireRejected = (label, events) => {
    if (!inventoryFailures(events, expectedEvents).length) throw new Error(`54-occurrence source inventory accepted ${label} mutant`);
  };
  requireRejected('missing top-level event', goodEvents.filter((event) => !(event.Test === genericTests[4].test && event.Action === 'run')));
  requireRejected('duplicate top-level event', [...goodEvents, { Action: 'run', Test: genericTests[4].test }]);
  requireRejected('extra top-level event', [...goodEvents, { Action: 'run', Test: 'TestCheckpointFixedLauncherUnexpected' }]);
  const childPath = `${genericTests[3].test}/${genericTests[3].subtests[0].replaceAll(' ', '_')}`;
  requireRejected('missing child event', goodEvents.filter((event) => event.Test !== childPath));
  requireRejected('duplicate child event', [...goodEvents, { Action: 'run', Test: childPath }]);
  requireRejected('extra child event', [...goodEvents, { Action: 'run', Test: `${genericTests[3].test}/unexpected_source_child` }]);
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 180_000, maxBuffer: 16 * 1024 * 1024, windowsHide: true, ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${program} exited ${result.status ?? 'without status'}: ${[(result.stderr ?? ''), (result.stdout ?? '')].filter(Boolean).join('\n').slice(-4000)}`);
  return result.stdout ?? '';
}

function parseJSONEvents(output, label) {
  const events = []; const failures = [];
  for (const [index, line] of output.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try { events.push(JSON.parse(line)); } catch { failures.push(`non-JSON event at ${label}:${index + 1}`); }
  }
  return { events, failures };
}

function parseVerboseEvents(output) {
  const events = [];
  for (const line of output.split(/\r?\n/)) {
    let match = line.match(/^=== RUN\s+(\S+)/); if (match) { events.push({ Action: 'run', Test: match[1] }); continue; }
    match = line.match(/^\s*--- PASS:\s+(\S+)/); if (match) { events.push({ Action: 'pass', Test: match[1] }); continue; }
    match = line.match(/^\s*--- SKIP:\s+(\S+)/); if (match) { events.push({ Action: 'skip', Test: match[1] }); continue; }
    match = line.match(/^\s*--- FAIL:\s+(\S+)/); if (match) events.push({ Action: 'fail', Test: match[1] });
  }
  return events;
}

function verifyTestEvents(events, features, failures = []) {
  failures.push(...inventoryFailures(events, features));
  for (const event of events) if (event.Action === 'fail' && !event.Test) failures.push(`package-level failure ${event.Package ?? ''}`);
  return failures;
}

function runWindowsGoTests(features) {
  const pattern = `^(${features.map((item) => item.test).join('|')})$`;
  const result = spawnSync('go', ['test', '-count=1', '-json', '-timeout=40s', '-run', pattern, './internal/nodeagent'], {
    cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 16 * 1024 * 1024, windowsHide: true,
  });
  if (result.error) throw result.error;
  const { events, failures } = parseJSONEvents(result.stdout ?? '', 'Windows go test');
  if (result.status !== 0) failures.push(`go test exited ${result.status ?? 'unknown'}`);
  failures.push(...verifyTestEvents(events, eventFeatures(features)));
  if (failures.length) throw new Error(`Windows test event inventory failed: ${[...new Set(failures)].join('; ')}`);
}

function runLinuxFixture(features) {
  if (process.platform === 'linux') {
    const pattern = `^(${features.map((item) => item.test).join('|')})$`;
    const result = spawnSync('go', ['test', '-count=1', '-json', '-timeout=40s', '-run', pattern, './internal/nodeagent'], {
      cwd: root, encoding: 'utf8', timeout: 60_000, maxBuffer: 16 * 1024 * 1024,
    });
    if (result.error) throw result.error;
    const { events, failures } = parseJSONEvents(result.stdout ?? '', 'Linux go test');
    if (result.status !== 0) failures.push(`go test exited ${result.status ?? 'unknown'}`);
    failures.push(...verifyTestEvents(events, eventFeatures(features)));
    if (failures.length) throw new Error(`Linux test event inventory failed: ${[...new Set(failures)].join('; ')}`);
    return;
  }
  const temp = mkdtempSync(join(tmpdir(), 'checkpoint-fixed-launcher-'));
  try {
    const testBinary = join(temp, 'nodeagent-linux.test');
    const linuxEnv = { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' };
    run('go', ['test', '-c', '-o', testBinary, './internal/nodeagent'], { env: linuxEnv });
    run('go', ['build', '-o', join(temp, 'checkpoint-fixed-launcher-linux'), './cmd/checkpoint-fixed-launcher'], { env: linuxEnv });
    const distributions = run('wsl.exe', ['--list', '--quiet']).replaceAll('\0', '');
    assert.ok(distributions.split(/\r?\n/).some((line) => line.trim() === 'Ubuntu'), 'inspected Ubuntu WSL distribution is unavailable');
    const linuxPath = run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'wslpath', '-a', testBinary]).trim();
    const output = run('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxPath, '-test.v', '-test.count=1', '-test.timeout=40s', `-test.run=^(${features.map((item) => item.test).join('|')})$`]);
    const failures = verifyTestEvents(parseVerboseEvents(output), eventFeatures(features));
    if (failures.length) throw new Error(`WSL Linux test event inventory failed: ${[...new Set(failures)].join('; ')}`);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

function eventFeatures(features) {
  return features.map((feature) => ({ ...feature, subtests: (feature.subtests ?? []).map((subtest) => subtest.replaceAll(' ', '_')) }));
}

function verifyNativeCommandBuild() {
  const temp = mkdtempSync(join(tmpdir(), 'checkpoint-fixed-launcher-command-'));
  try {
    const binary = join(temp, process.platform === 'win32' ? 'checkpoint-fixed-launcher.exe' : 'checkpoint-fixed-launcher');
    run('go', ['build', '-o', binary, './cmd/checkpoint-fixed-launcher']);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

selfCheckInventoryOracle();
if (mode === 'source') {
  sourceInventoryControls();
  console.log('fixed checkpoint launcher source inventory controls passed');
} else {
  const windowsFeatures = mode === 'faults' ? [genericTests[3]] : genericTests;
  const linuxFeatures = mode === 'default' || mode === 'bounds'
    ? linuxTests
    : [linuxTests[0], linuxTests[1], linuxTests[2], linuxTests[4], linuxTests[5], linuxTests[6], linuxTests[7], linuxTests[8], linuxTests[9], linuxTests[10]];
  runWindowsGoTests(windowsFeatures);
  runLinuxFixture(linuxFeatures);
  if (mode === 'default' || mode === 'bounds') {
    verifyNativeCommandBuild();
  }
  console.log(`fixed checkpoint launcher ${mode} verification passed`);
}
