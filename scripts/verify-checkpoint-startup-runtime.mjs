#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const owned = {
  plan: 'internal/nodeagent/checkpoint_launch_plan.go',
  planTests: 'internal/nodeagent/checkpoint_launch_plan_test.go',
  launcher: 'internal/nodeagent/checkpoint_fixed_launcher.go',
  launcherTests: 'internal/nodeagent/checkpoint_fixed_launcher_test.go',
};
const requiredTests = [
  'TestCheckpointLaunchPlanRuntimeOptionsSchema',
  'TestCheckpointFixedLauncherRuntimeOptionsCommand',
  'TestCheckpointLaunchPlanRuntimeOptionsSpecCopy',
];
const schemaSubtests = [
  'v1_presence', 'explicit_null', 'missing_kv_unified', 'missing_flash_attention',
  'missing_checkpoint_descriptor', 'unknown_nested_key', 'case_aliased_nested_key',
  'duplicate_root_key', 'duplicate_nested_key', 'kv_unified_false',
  'flash_attention_on', 'descriptor_false',
].map((name) => `TestCheckpointLaunchPlanRuntimeOptionsSchema/${name}`);
const packageName = 'vram-governor/internal/nodeagent';
const requiredTerminalTests = [...requiredTests, ...schemaSubtests];
const unitRun = `^(${requiredTests.join('|')})$`;

function fail(message) {
  throw new Error(message);
}

function readOwned(relative) {
  const absolute = path.join(root, relative);
  if (!fs.existsSync(absolute) || !fs.statSync(absolute).isFile()) {
    fail(`required source is missing: ${relative}`);
  }
  return fs.readFileSync(absolute, 'utf8');
}

function assertSourceContract(plan, launcher, planTests, launcherTests) {
  const checks = [
    [plan, /RuntimeOptions\s+\*CheckpointLaunchRuntimeOptions\s+`json:"runtime_options,omitempty"`/, 'typed optional runtime_options pointer'],
    [plan, /type CheckpointLaunchRuntimeOptions struct[\s\S]*?KVUnified\s+bool\s+`json:"kv_unified"`[\s\S]*?FlashAttention\s+string\s+`json:"flash_attention"`[\s\S]*?CheckpointDescriptor\s+bool\s+`json:"checkpoint_descriptor"`/, 'exact typed nested runtime options'],
    [plan, /rootFields\["runtime_options"\]/, 'v2 canonical root allowlist'],
    [plan, /allowed\["\$\.runtime_options"\]\s*=\s*map\[string\]struct\{\}\s*\{"kv_unified": \{\}, "flash_attention": \{\}, "checkpoint_descriptor": \{\}\}/, 'closed nested key allowlist'],
    [plan, /field == "runtime_options"[\s\S]*?continue/, 'only absent v2 runtime_options is optional'],
    [plan, /validateCheckpointLaunchRuntimeOptions\(p\.Version, p\.RuntimeOptions\)/, 'parsed plan tuple validation'],
    [plan, /options\.KVUnified\s*\|\|\s*options\.FlashAttention\s*!=\s*"off"\s*\|\|\s*!options\.CheckpointDescriptor/, 'fail-closed exact supported tuple'],
    [plan, /func fixedCheckpointPlacementArguments[\s\S]*?validateCheckpointLaunchRuntimeOptions\(p\.Version, p\.RuntimeOptions\)/, 'direct value validation before fixed argv'],
    [plan, /args = append\(args, "--kv-unified", "--flash-attn", "off"\)/, 'only fixed supported runtime argv'],
    [plan, /if p\.plan\.RuntimeOptions != nil[\s\S]*?spec\.RuntimeOptions = &options/, 'defensive Spec pointer copy'],
    [launcher, /args, err := fixedCheckpointPlacementArguments\(plan\)[\s\S]*?cmd := fixedCheckpointCommand\(executable, args\)[\s\S]*?cmd\.Env = runtimeCheckpointChildEnvironment\(placement\.ChildMaskUUID\)[\s\S]*?if plan\.RuntimeOptions != nil[\s\S]*?LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=1/, 'fixed descriptor environment only after validated placement argv'],
    [planTests, /func TestCheckpointLaunchPlanRuntimeOptionsSchema\(/, 'strict parser and invalid tuple tests'],
    [launcherTests, /func TestCheckpointFixedLauncherRuntimeOptionsCommand\(/, 'exact argv and environment tests'],
    [launcherTests, /func TestCheckpointLaunchPlanRuntimeOptionsSpecCopy\(/, 'deep-copy test'],
  ];
  for (const [source, pattern, label] of checks) {
    if (!pattern.test(source)) fail(`source contract is missing or weakened: ${label}`);
  }
  const inventory = testInventory(planTests, launcherTests);
  const expected = [...requiredTests].sort();
  if (inventory.length !== expected.length || inventory.some((name, i) => name !== expected[i])) {
    fail(`startup test inventory mismatch: found ${inventory.join(', ') || '(none)'}`);
  }
}

function testInventory(...sources) {
  const found = [];
  for (const source of sources) {
    for (const match of source.matchAll(/^func\s+(Test[A-Za-z0-9_]*)\s*\(/gm)) found.push(match[1]);
  }
  const counts = new Map();
  for (const name of found) counts.set(name, (counts.get(name) ?? 0) + 1);
  for (const required of requiredTests) {
    const count = counts.get(required) ?? 0;
    if (count !== 1) fail(`startup test ${required} occurs ${count} times; expected exactly once`);
  }
  return requiredTests.filter((name) => (counts.get(name) ?? 0) === 1).sort();
}

function runSourceControls() {
  const plan = readOwned(owned.plan);
  const planTests = readOwned(owned.planTests);
  const launcher = readOwned(owned.launcher);
  const launcherTests = readOwned(owned.launcherTests);
  assertSourceContract(plan, launcher, planTests, launcherTests);

  // Prove the inventory oracle catches both omission and duplication.
  const omitted = launcherTests.replace(/^func TestCheckpointFixedLauncherRuntimeOptionsCommand\(/m, 'func RemovedCheckpointFixedLauncherRuntimeOptionsCommand(');
  expectRejected(() => testInventory(planTests, omitted), 'missing-test inventory control');
  const duplicate = `${launcherTests}\nfunc TestCheckpointLaunchPlanRuntimeOptionsSpecCopy(t *testing.T) {}`;
  expectRejected(() => testInventory(planTests, duplicate), 'duplicate-test inventory control');

  // Positive broken-source controls demonstrate that each security assertion
  // is sensitive to a broken implementation, not merely to file presence.
  expectRejected(() => assertSourceContract(
    plan.replace('args = append(args, "--kv-unified", "--flash-attn", "off")', 'args = append(args, "--flash-attn", "auto")'),
    launcher, planTests, launcherTests), 'unsupported argv mutant');
  expectRejected(() => assertSourceContract(
    plan, launcher.replace('LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=1', 'LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=0'), planTests, launcherTests), 'descriptor opt-in mutant');

  // The source path returns before the sole child-process entry point. The
  // unit runner itself contains no WSL, remote or fallback execution route.
  const self = fs.readFileSync(fileURLToPath(import.meta.url), 'utf8');
  assertUnitRunnerContract(self);
  const runner = unitRunnerSource(self);
  const terminalControls = successfulTerminalFixture();
  validateUnitEvents(terminalControls);
  expectRejected(() => validateUnitEvents([{ Action: 'pass', Package: packageName }]), 'zero terminal inventory control');
  expectRejected(() => validateUnitEvents([...terminalControls, { Action: 'fail', Package: packageName }]), 'package FAIL alongside PASS control');
  expectRejected(() => validateUnitEvents([...terminalControls, { Action: 'skip', Package: packageName }]), 'package SKIP alongside PASS control');
  expectRejected(() => validateUnitEvents(terminalControls.map((event) => !event.Test ? { ...event, Action: 'fail' } : event)), 'package FAIL control');
  expectRejected(() => validateUnitEvents(terminalControls.map((event) => !event.Test ? { ...event, Action: 'skip' } : event)), 'package SKIP control');
  expectRejected(() => validateUnitEvents([...terminalControls, terminalControls.find((event) => event.Test === requiredTests[0])]), 'duplicate terminal control');
  expectRejected(() => validateUnitEvents([...terminalControls, { Action: 'pass', Package: packageName, Test: 'TestCheckpointUnexpected' }]), 'unexpected terminal control');
  expectRejected(() => validateUnitEvents(terminalControls.map((event) => event.Test === schemaSubtests[0] ? { ...event, Action: 'skip' } : event)), 'skipped terminal control');
  expectRejected(() => validateUnitEvents(terminalControls.map((event) => event.Test === schemaSubtests[0] ? { ...event, Action: 'fail' } : event)), 'failed terminal control');
  expectRejected(() => validateUnitEvents(terminalControls.map((event) => event.Test ? { ...event, Package: 'other/package' } : event)), 'wrong package control');
  const sourceBranch = self.indexOf("if (mode === '--source'");
  const unitBranch = self.indexOf("else if (mode === '--unit'");
  const sourceBranchEnd = self.indexOf('} else if', sourceBranch);
  if (sourceBranch < 0 || unitBranch < 0 || sourceBranchEnd < 0 || sourceBranchEnd <= sourceBranch ||
      /spawnSync|runUnit\(/.test(self.slice(sourceBranch, sourceBranchEnd)) ||
      !/if \(process\.platform !== 'linux'\) fail\('unit mode is supported only on Linux'\);\s*const version = spawnSync/.test(self)) {
    fail('source-only routing or local-only unit boundary is not explicit');
  }
  process.stdout.write('checkpoint startup runtime source controls passed\n');
}

function assertUnitRunnerContract(source) {
  const runner = unitRunnerSource(source);
  const rules = [
    [/if \(process\.platform !== 'linux'\) fail\('unit mode is supported only on Linux'\);\s*const version = spawnSync/, 'Linux rejection before process spawn'],
    [/go version go1\\\.23\\\.4 linux\\\//, 'exact local Go 1.23.4 pin'],
    [/result\.status !== 0/, 'unit process exit status'],
    [/validateUnitEvents\(events\)/, 'exact output event validator'],
    [/spawnSync\('go', \['test', '-count=1', '-json', '\.\/internal\/nodeagent', '-run', unitRun\]/, 'uncached execution of declared Go unit tests'],
  ];
  for (const [pattern, label] of rules) if (!pattern.test(runner)) fail(`unit runner contract is missing: ${label}`);
  const validation = runner.indexOf('validateUnitEvents(events)');
  const marker = runner.indexOf("process.stdout.write('checkpoint startup runtime unit controls passed\\n')");
  if (validation < 0 || marker < validation) fail('unit success marker can precede terminal inventory validation');
}

function unitRunnerSource(source) {
  const start = source.indexOf('function runUnit()');
  const end = source.indexOf('\n}\n\nconst mode =', start);
  return start < 0 || end < 0 ? '' : source.slice(start, end + 2);
}

function expectRejected(run, label) {
  let rejected = false;
  try { run(); } catch { rejected = true; }
  if (!rejected) fail(`${label} was accepted by its oracle`);
}

function successfulTerminalFixture() {
  return [
    { Action: 'pass', Package: packageName },
    ...requiredTests.map((Test) => ({ Action: 'pass', Package: packageName, Test })),
    ...schemaSubtests.map((Test) => ({ Action: 'pass', Package: packageName, Test })),
  ];
}

function validateUnitEvents(events) {
  if (!Array.isArray(events) || events.some((event) => event.Package !== packageName)) {
    fail('unit output contains an unexpected package identity');
  }
  const packageTerminals = events.filter((event) => !event.Test && ['pass', 'skip', 'fail'].includes(event.Action));
  if (packageTerminals.length !== 1 || packageTerminals[0].Action !== 'pass') fail('unit output lacks one unique package PASS or contains a skipped/failed package');
  const testTerminals = events.filter((event) => event.Test && ['pass', 'skip', 'fail'].includes(event.Action));
  if (!testTerminals.length || testTerminals.some((event) => event.Action !== 'pass')) {
    fail('unit inventory is empty or contains a skipped/failed test');
  }
  const seen = new Set();
  for (const event of testTerminals) {
    const key = `${event.Package}\0${event.Test}`;
    if (seen.has(key)) fail(`duplicate terminal test event: ${event.Test}`);
    seen.add(key);
  }
  const expected = new Set(requiredTerminalTests);
  if (seen.size !== expected.size || [...seen].some((key) => !expected.has(key.slice(key.indexOf('\0') + 1)))) {
    fail('unit terminal inventory differs from the exact declared tests and schema subtests');
  }
  for (const name of expected) if (!seen.has(`${packageName}\0${name}`)) fail(`unit terminal inventory is missing ${name}`);
}

function runUnit() {
  // Host gating is intentionally before spawnSync: unsupported hosts cannot
  // start Go, WSL, a container, or any substitute runner.
  if (process.platform !== 'linux') fail('unit mode is supported only on Linux');
  const version = spawnSync('go', ['version'], { cwd: root, encoding: 'utf8', timeout: 5000, windowsHide: true });
  if (version.error || version.status !== 0 || !/^go version go1\.23\.4 linux\//.test((version.stdout ?? '').trim())) {
    fail(`unit mode requires local Linux Go 1.23.4: ${(version.stderr ?? version.stdout ?? version.error?.message ?? '').trim()}`);
  }
  const result = spawnSync('go', ['test', '-count=1', '-json', './internal/nodeagent', '-run', unitRun], {
    cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.status !== 0) fail(`Go unit process failed (${result.status ?? 'not started'}): ${(result.stderr ?? result.error?.message ?? '').trim()}`);
  const events = [];
  for (const line of (result.stdout ?? '').split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { fail('go test -json emitted a malformed event line'); }
    events.push(event);
  }
  validateUnitEvents(events);
  process.stdout.write('checkpoint startup runtime unit controls passed\n');
}

const mode = process.argv[2];
try {
  if (mode === '--source' && process.argv.length === 3) {
    runSourceControls();
    process.exitCode = 0;
  } else if (mode === '--unit' && process.argv.length === 3) {
    runUnit();
    process.exitCode = 0;
  } else {
    fail('usage: verify-checkpoint-startup-runtime.mjs --source | --unit');
  }
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
