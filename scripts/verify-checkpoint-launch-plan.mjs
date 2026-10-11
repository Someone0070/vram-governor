import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && !['--source', '--faults', '--bounds'].includes(args[0]))) {
  console.error('usage: node scripts/verify-checkpoint-launch-plan.mjs [--source|--faults|--bounds]');
  process.exit(2);
}
const mode = args[0] ?? '';
const commonTests = [
  'TestCheckpointLaunchPlanBoundsAndArguments',
  'TestCheckpointLaunchPlanPathSyntaxRejectsTraversalAndControls',
];
const linuxTests = [
  'TestCheckpointLaunchPlanRuntimeOptionsSchema',
  'TestCheckpointLaunchPlanStrictParsing',
  'TestCheckpointLaunchPlanInvalidJSON',
  'TestCheckpointLaunchPlanPinnedRecheck',
  'TestCheckpointLaunchPlanDefensiveCopies',
  'TestCheckpointLaunchPlanCancellationClosedAndPublicUID',
  'TestCheckpointLaunchPlanUnsafeFileAndParents',
  'TestCheckpointLaunchPlanRecheckCanceledContext',
  'TestCheckpointLaunchPlanV2PlacementStrictParsing',
];
const allTests = [...commonTests, ...linuxTests];
if (allTests.length !== 11) throw new Error(`feature inventory must contain exactly 11 tests, got ${allTests.length}`);
const subtests = {
  TestCheckpointLaunchPlanStrictParsing: ['duplicate', 'nested_duplicate', 'nested_unknown', 'unknown', 'casefold_alias', 'casefold_nested_path', 'missing_reserve_field', 'null_reserve_field', 'null_host', 'invalid_UTF-8', 'trailing', 'oversized', 'noninteger', 'wrong_type', 'slots_int64_max', 'slots_over_int64'],
  TestCheckpointLaunchPlanInvalidJSON: ['alias', 'sha', 'endpoint', 'endpoint_URL', 'context_low', 'context_slot_mismatch', 'slot_overflow_bound', 'slots_high', 'artifact_quota_low', 'artifact_quota_high', 'staging_quota_high', 'staging_model_plus_reserve', 'reserve_quota', 'path_traversal'],
  TestCheckpointLaunchPlanV2PlacementStrictParsing: ['missing_placement', 'duplicate_device_token', 'casefold_physical_identity', 'unexpected_placement_field'],
  TestCheckpointLaunchPlanPinnedRecheck: ['stable', 'pathname_replacement', 'same_inode_mutation'],
  TestCheckpointLaunchPlanUnsafeFileAndParents: ['hard_link', 'writable_plan_file', 'fifo_nonblocking', 'symlink', 'public_root_directory_mode', 'parent_identity_change'],
  TestCheckpointLaunchPlanRuntimeOptionsSchema: ['v1_presence', 'explicit_null', 'missing_kv_unified', 'missing_flash_attention', 'missing_checkpoint_descriptor', 'unknown_nested_key', 'case_aliased_nested_key', 'duplicate_root_key', 'duplicate_nested_key', 'kv_unified_false', 'flash_attention_on', 'descriptor_false'],
};
const allEvents = allTests.flatMap((name) => [name, ...(subtests[name] ?? []).map((subtest) => `${name}/${subtest}`)]);
if (new Set(allEvents).size !== allEvents.length) throw new Error('feature event inventory contains duplicates');
const sourcePaths = [
  'internal/nodeagent/checkpoint_launch_plan_test.go',
  'internal/nodeagent/checkpoint_launch_plan_linux_test.go',
];
const testSource = sourcePaths.map(file => readFileSync(path.join(repoRoot, file), 'utf8')).join('\n');
const schemaRawLabels = [
  'v1 presence', 'explicit null', 'missing kv_unified', 'missing flash_attention',
  'missing checkpoint_descriptor', 'unknown nested key', 'case aliased nested key',
  'duplicate root key', 'duplicate nested key', 'kv_unified false',
  'flash attention on', 'descriptor false',
];

function schemaChildLabels(source) {
  const functionStart = source.indexOf('func TestCheckpointLaunchPlanRuntimeOptionsSchema(');
  if (functionStart < 0) return null;
  const nextFunction = source.indexOf('\nfunc ', functionStart + 1);
  const functionBody = source.slice(functionStart, nextFunction < 0 ? source.length : nextFunction);
  const casesStart = functionBody.indexOf('badOptions := []struct {');
  const loopStart = functionBody.indexOf('for _, tc := range badOptions {', casesStart);
  if (casesStart < 0 || loopStart < 0) return null;
  return [...functionBody.slice(casesStart, loopStart).matchAll(/\{\s*"([^"\n]+)"\s*,/g)].map(match => match[1]);
}

function sourceInventoryFailures(source) {
  const failures = [];
  const declared = [...source.matchAll(/^func (Test\w+)\(/gm)].map(match => match[1]);
  const unique = new Set(declared);
  const missing = allTests.filter(name => !declared.includes(name));
  const unexpected = declared.filter(name => !allTests.includes(name));
  if (unique.size !== declared.length) failures.push('duplicate top declaration');
  if (missing.length || unexpected.length || declared.length !== allTests.length) failures.push('top inventory mismatch');
  if (/\bt\.Skip(?:f|Now)?\s*\(/.test(source)) failures.push('test skip present');
  for (const [test, cases] of Object.entries(subtests)) {
    if (test === 'TestCheckpointLaunchPlanRuntimeOptionsSchema') continue;
    for (const name of cases) {
      // These inherited labels historically use spaces for Go's normalized
      // underscores. The runtime-options labels are checked raw below because
      // `kv_unified` and similar underscores are literal source characters.
      if (!source.includes(`"${name.replaceAll('_', ' ')}"`)) failures.push(`missing inherited subtest ${test}/${name}`);
    }
  }
  const rawChildren = schemaChildLabels(source);
  if (rawChildren === null) failures.push('schema child source missing');
  else {
    if (new Set(rawChildren).size !== rawChildren.length) failures.push('duplicate schema child declaration');
    if (rawChildren.length !== schemaRawLabels.length || rawChildren.some((name, index) => name !== schemaRawLabels[index])) {
      failures.push('schema child inventory mismatch');
    }
    const normalized = rawChildren.map(name => name.replaceAll(' ', '_'));
    const expectedNormalized = subtests.TestCheckpointLaunchPlanRuntimeOptionsSchema;
    if (normalized.length !== expectedNormalized.length || normalized.some((name, index) => name !== expectedNormalized[index])) {
      failures.push('normalized schema child inventory mismatch');
    }
  }
  return failures;
}

function assertSourceInventory(source, label) {
  const failures = sourceInventoryFailures(source);
  if (failures.length) throw new Error(`${label}: ${[...new Set(failures)].join('; ')}`);
}

assertSourceInventory(testSource, 'feature source inventory mismatch');

function sourceSelectorBeforeEffects(scriptSource) {
  const selector = "if (mode === '--source') {\n  checkSourceInventoryOracle();\n  console.log('checkpoint launch plan source inventory controls passed');\n  process.exit(0);\n}";
  const selectorAt = scriptSource.indexOf(selector);
  const exitAt = selectorAt < 0 ? -1 : selectorAt + selector.length;
  const tempAt = scriptSource.search(/^const tempDir = mkdtempSync\(path\.join\(tmpdir\(\), 'checkpoint-launch-plan-'\)\);/m);
  return selectorAt >= 0 && scriptSource.indexOf(selector, selectorAt + 1) < 0 && exitAt > selectorAt && tempAt > exitAt;
}

function platformSelectionFailures(scriptSource) {
  const schemaTest = 'TestCheckpointLaunchPlanRuntimeOptionsSchema';
  const commonMatch = scriptSource.match(/const commonTests = \[([\s\S]*?)\n\];/);
  const linuxMatch = scriptSource.match(/const linuxTests = \[([\s\S]*?)\n\];/);
  const failures = [];
  if (!commonMatch || commonMatch[1].includes(schemaTest)) failures.push('schema test selected natively');
  if (!linuxMatch || !linuxMatch[1].includes(schemaTest)) failures.push('schema test missing from Linux selection');
  if (!scriptSource.includes('const nativeTests = linuxHost ? allTests : commonTests;')) failures.push('native test selector mismatch');
  if (!/^  if \(windowsHost\) runLinuxFeatures\(linuxTests, 'nodeagent-linux\.test'\);$/m.test(scriptSource)) failures.push('Windows Linux test invocation missing');
  return failures;
}

function checkSourceInventoryOracle() {
  const controls = [
    ['positive', testSource, null],
    ['missing top', testSource.replace('func TestCheckpointLaunchPlanRuntimeOptionsSchema(', 'func TestCheckpointLaunchPlanRuntimeOptionsSchemaMissing('), 'top inventory mismatch'],
    ['extra top', `${testSource}\nfunc TestCheckpointLaunchPlanUnexpected(t *testing.T) {}`, 'top inventory mismatch'],
    ['duplicate top', `${testSource}\nfunc TestCheckpointLaunchPlanBoundsAndArguments(t *testing.T) {}`, 'duplicate top declaration'],
    ['missing child', testSource.replace('{"v1 presence",', '{"removed v1 presence",'), 'schema child inventory mismatch'],
    ['extra child', testSource.replace('for _, tc := range badOptions {', '{"future option", string(valid)},\n\tfor _, tc := range badOptions {'), 'schema child inventory mismatch'],
    ['duplicate child', testSource.replace('{"v1 presence",', '{"v1 presence", string(valid)},\n\t\t{"v1 presence",'), 'duplicate schema child declaration'],
  ];
  for (const [name, source, expectedFailure] of controls) {
    const failures = sourceInventoryFailures(source);
    if (name === 'positive') {
      if (failures.length) throw new Error(`source inventory positive control failed: ${failures.join('; ')}`);
    } else if (!failures.includes(expectedFailure)) {
      throw new Error(`source inventory negative control did not reject ${name}: ${failures.join('; ') || 'accepted'}`);
    }
  }
  const scriptSource = readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const selectionFailures = platformSelectionFailures(scriptSource);
  if (selectionFailures.length) throw new Error(`platform test selection mismatch: ${selectionFailures.join('; ')}`);
  const nativeMisclassification = scriptSource.replace(
    "  'TestCheckpointLaunchPlanPathSyntaxRejectsTraversalAndControls',\n];",
    "  'TestCheckpointLaunchPlanPathSyntaxRejectsTraversalAndControls',\n  'TestCheckpointLaunchPlanRuntimeOptionsSchema',\n];",
  );
  const missingLinuxSchema = scriptSource.replace("  'TestCheckpointLaunchPlanRuntimeOptionsSchema',\n", '');
  const missingWindowsLinuxInvocation = scriptSource.replace(/^  if \(windowsHost\) runLinuxFeatures\(linuxTests, 'nodeagent-linux\.test'\);\r?\n/m, '');
  if (!platformSelectionFailures(nativeMisclassification).includes('schema test selected natively') ||
      !platformSelectionFailures(missingLinuxSchema).includes('schema test missing from Linux selection') ||
      !platformSelectionFailures(missingWindowsLinuxInvocation).includes('Windows Linux test invocation missing')) {
    throw new Error('platform test selection negative control accepted a native schema run or missing Linux invocation');
  }
  if (!sourceSelectorBeforeEffects(scriptSource)) throw new Error('source selector must exit before private temp/cache/compiler/WSL setup');
  const selectorBranch = "if (mode === '--source') {\n  checkSourceInventoryOracle();\n  console.log('checkpoint launch plan source inventory controls passed');\n  process.exit(0);\n}";
  const missingSelector = scriptSource.replace(selectorBranch, '');
  const lateSelector = `const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-launch-plan-'));\n${selectorBranch}`;
  if (sourceSelectorBeforeEffects(missingSelector) || sourceSelectorBeforeEffects(lateSelector)) {
    throw new Error('source selector ordering control accepted a missing or late dispatch');
  }
}

function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: repoRoot, env, encoding: 'utf8', timeout: 600_000, maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.error) throw new Error(`${program} failed to start or timed out: ${result.error.message}`);
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (program === 'wsl.exe' && output.includes('E_ACCESSDENIED')) {
    throw new Error('WSL Linux artifact run denied by the sandbox (Wsl/Service/E_ACCESSDENIED); root execution is required. No retry or workaround was attempted.');
  }
  if (result.status !== 0 || result.signal != null) throw new Error(`${program} exited ${result.status ?? 'without a status'}\n${output}`);
  return output;
}

function inventoryFailures(events, expected) {
  const failures = [];
  const records = new Map(expected.map((name) => [name, { runs: 0, terminal: [] }]));
  if (records.size !== expected.length) failures.push('duplicate expected event path');
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

function parseTestEvents(output) {
  const events = [];
  const failures = [];
  for (const line of output.split(/\r?\n/)) {
    const text = line.trim();
    if (!text) continue;
    try {
      const event = JSON.parse(text);
      if (event.Test && ['run', 'pass', 'skip', 'fail'].includes(event.Action)) events.push(event);
    } catch {
      let match = text.match(/^=== RUN\s+(\S+)/);
      if (match) { events.push({ Action: 'run', Test: match[1] }); continue; }
      match = text.match(/^--- PASS:\s+(\S+)/);
      if (match) { events.push({ Action: 'pass', Test: match[1] }); continue; }
      match = text.match(/^--- SKIP:\s+(\S+)/);
      if (match) { events.push({ Action: 'skip', Test: match[1] }); continue; }
      match = text.match(/^--- FAIL:\s+(\S+)/);
      if (match) { events.push({ Action: 'fail', Test: match[1] }); continue; }
      if (text === 'PASS' || /^ok\s/.test(text)) continue;
      failures.push(`unrecognized test output: ${text.slice(0, 120)}`);
    }
  }
  return { events, failures };
}

function assertPassed(output, expected, label) {
  const parsed = parseTestEvents(output);
  const failures = [...parsed.failures, ...inventoryFailures(parsed.events, expected)];
  if (failures.length) throw new Error(`${label} did not pass exact RUN/PASS inventory: ${[...new Set(failures)].join('; ')}`);
}

function checkInventoryOracle() {
  const expected = ['T', 'T/sub'];
  const good = [{ Action: 'run', Test: 'T' }, { Action: 'run', Test: 'T/sub' }, { Action: 'pass', Test: 'T/sub' }, { Action: 'pass', Test: 'T' }];
  const controls = [
    ['positive', good, false],
    ['missing run', good.filter((event) => event.Test !== 'T/sub' || event.Action !== 'run'), true],
    ['missing terminal', good.slice(0, 3), true],
    ['duplicate run', [...good, { Action: 'run', Test: 'T' }], true],
    ['duplicate terminal', [...good, { Action: 'pass', Test: 'T/sub' }], true],
    ['skip', good.map((event) => event.Test === 'T/sub' && event.Action === 'pass' ? { ...event, Action: 'skip' } : event), true],
    ['fail', good.map((event) => event.Test === 'T/sub' && event.Action === 'pass' ? { ...event, Action: 'fail' } : event), true],
    ['unexpected', [...good, { Action: 'run', Test: 'T/extra' }], true],
  ];
  for (const [name, events, shouldFail] of controls) {
    if ((inventoryFailures(events, expected).length > 0) !== shouldFail) throw new Error(`strict test inventory oracle control failed: ${name}`);
  }
}

function runNative(names) {
  const output = run('go', ['test', '-json', './internal/nodeagent', '-run', `^(${names.join('|')})$`, '-count=1', '-timeout=30s']);
  assertPassed(output, names.flatMap((name) => [name, ...(subtests[name] ?? []).map((subtest) => `${name}/${subtest}`)]), 'native feature suite');
}

function runExpectedFailure(program, commandArgs, expectedTest, marker, options = {}) {
  const result = spawnSync(program, commandArgs, {
    cwd: repoRoot, env, encoding: 'utf8', timeout: 60_000, maxBuffer: 8 * 1024 * 1024, ...options,
  });
  if (result.error) throw new Error(`${program} mutant failed to start or timed out: ${result.error.message}`);
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (program === 'wsl.exe' && output.includes('E_ACCESSDENIED')) {
    throw new Error('WSL Linux mutant run denied by the sandbox (Wsl/Service/E_ACCESSDENIED); root execution is required. No retry or workaround was attempted.');
  }
  if (result.status !== 1 || result.signal != null) throw new Error(`${program} mutant did not fail with a normal assertion (status=${result.status}, signal=${result.signal ?? 'none'})\n${output}`);
  if (!output.includes(`--- FAIL: ${expectedTest}`) || !output.includes(marker) || /panic:|fatal error:|test timed out/i.test(output)) {
    throw new Error(`${program} mutant lacked its named fixture assertion or terminated abnormally\n${output}`);
  }
  return output;
}

function runWslBinary(binaryPath, names) {
  const linuxPath = windowsPathToWslPath(binaryPath);
  run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'chmod', '+x', linuxPath]);
  const output = run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', linuxPath, `-test.run=^(${names.join('|')})$`, '-test.count=1', '-test.timeout=30s', '-test.v']);
  assertPassed(output, names.flatMap((name) => [name, ...(subtests[name] ?? []).map((subtest) => `${name}/${subtest}`)]), 'WSL Linux feature suite');
}

function compileLinux(outputPath, overlayPath) {
  const commandArgs = ['test', '-c'];
  if (overlayPath) commandArgs.push(`-overlay=${overlayPath}`);
  commandArgs.push('-o', outputPath, './internal/nodeagent');
  run('go', commandArgs, { env: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' } });
}

function runLinuxFeatures(names, artifactName) {
  if (linuxHost) {
    runNative(names);
    return;
  }
  const binaryPath = path.join(tempDir, artifactName);
  compileLinux(binaryPath);
  runWslBinary(binaryPath, names);
}

function mutateOnOverlay(label, edits, testName, marker, host) {
  const mutatedBySource = new Map();
  for (const edit of edits) {
    const sourcePath = path.join(repoRoot, edit.source);
    const original = mutatedBySource.has(sourcePath) ? mutatedBySource.get(sourcePath) : readFileSync(sourcePath, 'utf8');
    if (original.split(edit.before).length !== 2) throw new Error(`${label} mutation anchor is not unique: ${edit.before}`);
    const mutated = original.replace(edit.before, edit.after);
    if (mutated === original) throw new Error(`${label} mutation did not alter its source`);
    mutatedBySource.set(sourcePath, mutated);
  }
  const replacements = {};
  let index = 0;
  for (const [sourcePath, mutated] of mutatedBySource) {
    const replacementPath = path.join(tempDir, `${label}-${index}.go`);
    writeFileSync(replacementPath, mutated, 'utf8');
    replacements[sourcePath] = replacementPath;
    index += 1;
  }
  const overlayPath = path.join(tempDir, `${label}.overlay.json`);
  writeFileSync(overlayPath, JSON.stringify({ Replace: replacements }), 'utf8');
  if (host === 'linux') {
    runExpectedFailure('go', ['test', `-overlay=${overlayPath}`, './internal/nodeagent', '-run', `^${testName}$`, '-count=1', '-timeout=30s', '-v'], testName, marker);
    return;
  }
  const binaryPath = path.join(tempDir, `${label}.test`);
  compileLinux(binaryPath, overlayPath);
  const linuxPath = binaryPathToWsl(binaryPath);
  run('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'chmod', '+x', linuxPath]);
  runExpectedFailure('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', linuxPath, `-test.run=^${testName}$`, '-test.count=1', '-test.timeout=30s', '-test.v'], testName, marker);
}

function runMutants(host) {
  const common = 'internal/nodeagent/checkpoint_launch_plan.go';
  const linux = 'internal/nodeagent/checkpoint_launch_plan_linux.go';
  mutateOnOverlay('duplicate-key', [{
    source: common,
    before: 'if _, exists := seen[key]; exists {',
    after: 'if _, exists := seen[key]; false && exists {',
  }], 'TestCheckpointLaunchPlanStrictParsing', 'accepted duplicate plan', host);
  mutateOnOverlay('casefold-key', [{
    source: common,
    before: 'if err := rejectNoncanonicalLaunchPlanKeys(raw); err != nil {\n\t\treturn p, err\n\t}',
    after: '// removed exact-case schema key guard',
  }], 'TestCheckpointLaunchPlanStrictParsing', 'accepted casefold alias plan', host);
  mutateOnOverlay('size-bound', [{
    source: common,
    before: 'if len(raw) == 0 || len(raw) > checkpointLaunchPlanMaxBytes {',
    after: 'if len(raw) == 0 {',
  }], 'TestCheckpointLaunchPlanStrictParsing', 'accepted oversized plan', host);
  mutateOnOverlay('root-owner', [
    { source: linux, before: 'if !info.Mode().IsRegular() || uid != expectedUID || nlink != 1 || mode&0022 != 0 || size < 1 || size > checkpointLaunchPlanMaxBytes {', after: 'if !info.Mode().IsRegular() || uid != expectedUID && false || nlink != 1 || mode&0022 != 0 || size < 1 || size > checkpointLaunchPlanMaxBytes {' },
    { source: linux, before: 'if d != dev || n != ino || s != size || u != uid || l != 1 || m&0022 != 0 {', after: 'if d != dev || n != ino || s != size || u != uid && false || l != 1 || m&0022 != 0 {' },
  ], 'TestCheckpointLaunchPlanCancellationClosedAndPublicUID', 'public policy accepted a non-root plan file', host);
  const binding = 'internal/nodeagent/checkpoint_device_binding.go';
  mutateOnOverlay('placement-ceiling', [{
    source: common,
    before: 'p.MaxAccelerators != 1',
    after: 'p.MaxAccelerators == 1',
  }], 'TestCheckpointPlacementRejectsUnsupportedCeilingAndPartialFallback', 'multi-accelerator placement ceiling was accepted', host);
  mutateOnOverlay('runtime-token', [{
    source: common,
    before: 'p.RuntimeDeviceToken != "CUDA0"',
    after: 'p.RuntimeDeviceToken == "CUDA0"',
  }], 'TestCheckpointPlacementRejectsUnsupportedCeilingAndPartialFallback', 'unverified runtime device token was accepted', host);
  mutateOnOverlay('physical-identity-join', [{
    source: binding,
    before: 'observation.PhysicalIdentity != spec.Placement.PhysicalIdentity',
    after: 'observation.PhysicalIdentity == spec.Placement.PhysicalIdentity',
  }], 'TestCheckpointPlacementRequiresFreshMatchingPhysicalIdentity', 'matching local placement rejected', host);
  mutateOnOverlay('offload-count', [{
    source: binding,
    before: 'evidence.LayersGPU != evidence.LayersTotal',
    after: 'evidence.LayersGPU == evidence.LayersTotal',
  }], 'TestCheckpointOffloadEvidenceRequiresActualAllLayerPlacement', 'positive measured full GPU evidence rejected', host);
}

function windowsPathToWslPath(value) {
  const parsed = path.win32.parse(value);
  const drive = parsed.root.match(/^([A-Za-z]):\\$/)?.[1];
  if (!drive) throw new Error(`cannot map path into Ubuntu WSL: ${value}`);
  const relative = value.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean);
  return `/mnt/${drive.toLowerCase()}/${relative.join('/')}`;
}

checkInventoryOracle();
if (mode === '--source') {
  checkSourceInventoryOracle();
  console.log('checkpoint launch plan source inventory controls passed');
  process.exit(0);
}

function binaryPathToWsl(binaryPath) { return windowsPathToWslPath(binaryPath); }

const linuxHost = process.platform === 'linux';
const windowsHost = process.platform === 'win32';
if (!linuxHost && !windowsHost) throw new Error(`unsupported verification host: ${process.platform}`);
const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-launch-plan-'));
const cache = path.join(repoRoot, '.unlazy/fleet-residency-v2/tmp/gocache-custody-current');
const env = { ...process.env, GOCACHE: cache };

try {
  const nativeTests = linuxHost ? allTests : commonTests;
  runNative(nativeTests);
  if (windowsHost) runLinuxFeatures(linuxTests, 'nodeagent-linux.test');
  if (mode === '--faults') {
    if (windowsHost) {
      // Mutant Linux binaries are built from Go overlays, then each named
      // assertion is run directly under root in the fixed Ubuntu WSL distro.
      runMutants('windows');
    } else {
      runMutants('linux');
    }
    console.log(`checkpoint launch plan fault verification passed; feature-tests=${allTests.length}; compiling-mutants=8`);
  } else if (mode === '--bounds') {
    console.log('checkpoint launch plan bounded verification passed');
  } else {
    console.log(`checkpoint launch plan verification passed; feature-tests=${allTests.length}`);
  }
} finally {
  rmSync(tempDir, { recursive: true, force: true });
}
