import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const go = process.env.GO || 'go';
const tests = [
  'TestPreemptionNilPlanVictimIgnoredWithoutMutation',
  'TestPreemptionCancelableRequiresConfirmedStop',
];
const requiredPasses = [
  tests[0],
  tests[1],
  `${tests[1]}/unsupported`,
  `${tests[1]}/other_error`,
];

function runGo(args, cwd = root) {
  return spawnSync(go, args, {
    cwd,
    env: { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || 'auto' },
    encoding: 'utf8',
    windowsHide: true,
    timeout: 90000,
  });
}

function outputOf(result) {
  return `${result.stdout || ''}${result.stderr || ''}`;
}

function eventsOf(output) {
  return output.split(/\r?\n/).filter(Boolean).flatMap((line) => {
    try { return [JSON.parse(line)]; } catch { return []; }
  });
}

function assertNoSkips(events, label) {
  const skipped = events.filter((event) => event.Action === 'skip');
  assert.deepEqual(skipped, [], `${label} skipped tests: ${skipped.map((event) => event.Test || event.Package || 'unknown').join(', ')}`);
}

function assertExecutedTests(result) {
  const output = outputOf(result);
  assert.equal(result.error, undefined, `go test could not run: ${result.error || ''}`);
  assert.equal(result.status, 0, `go test failed (status=${result.status})\n${output}`);
  const events = eventsOf(output);
  assertNoSkips(events, 'preemption stop guard verification');
  const passed = new Set(events.filter((event) => event.Action === 'pass' && event.Test).map((event) => event.Test));
  assert.deepEqual(requiredPasses.filter((name) => !passed.has(name)), [], 'required preemption stop guard tests/subtests did not execute and pass');
}

function runExactTests(cwd = root, testPattern = '^(' + tests.join('|') + ')$') {
  return runGo(['test', './internal/workloads', '-run', testPattern, '-count=1', '-timeout=30s', '-json'], cwd);
}

function assertUniqueAnchor(source, anchor, name) {
  const count = source.split(anchor).length - 1;
  assert.equal(count, 1, `${name} mutation anchor must occur exactly once; found ${count}`);
}

function assertIntendedMutationFailure(result, exactTest, parentTest, marker, faultName) {
  const output = outputOf(result);
  assert.equal(result.error, undefined, `${faultName} did not complete: ${result.error || ''}`);
  assert.equal(result.signal, null, `${faultName} ended by signal ${result.signal}`);
  assert.equal(result.status, 1, `${faultName} must return status 1 through its intended assertion (status=${result.status})\n${output}`);
  assert.equal(/panic:|test timed out|fatal error:|\[build failed\]|undefined:|cannot find module/i.test(output), false, `${faultName} received panic, timeout, or compile-error credit\n${output}`);
  const events = eventsOf(output);
  assertNoSkips(events, faultName);
  const failedTests = events.filter((event) => event.Action === 'fail' && event.Test).map((event) => event.Test);
  assert.deepEqual(failedTests.filter((name) => name !== exactTest && name !== parentTest), [], `${faultName} had unrelated failed tests: ${failedTests.join(', ')}`);
  assert.ok(failedTests.includes(exactTest), `${faultName} did not fail exact test ${exactTest}\n${output}`);
  const exactOutput = events
    .filter((event) => event.Action === 'output' && event.Test === exactTest)
    .map((event) => event.Output || '')
    .join('\n');
  assert.ok(exactOutput.includes(marker), `${faultName} exact test output did not include its intended assertion: ${marker}\n${exactOutput}`);
}

function runFaults() {
  // Establish the unmodified controls before mutating a temporary project.
  assertExecutedTests(runExactTests());

  const fixture = mkdtempSync(join(tmpdir(), 'preemption-stop-guards-'));
  try {
    cpSync(join(root, 'internal'), join(fixture, 'internal'), { recursive: true });
    cpSync(join(root, 'go.mod'), join(fixture, 'go.mod'));
    cpSync(join(root, 'go.sum'), join(fixture, 'go.sum'));
    const managerPath = join(fixture, 'internal', 'workloads', 'manager.go');
    const original = readFileSync(managerPath, 'utf8');

    const planGuard = 'candidate.Status != domain.WorkloadRunning || candidate.Execution == nil || candidate.Plan == nil';
    const withoutPlanGuard = 'candidate.Status != domain.WorkloadRunning || candidate.Execution == nil';
    assertUniqueAnchor(original, planGuard, 'removePlanGuard');
    writeFileSync(managerPath, original.replace(planGuard, withoutPlanGuard));
    const nilPlanPattern = `^${tests[0]}$`;
    assertIntendedMutationFailure(
      runExactTests(fixture, nilPlanPattern),
      tests[0],
      tests[0],
      'nil-plan victim guard assertion: tryPreempt panicked on a victim with no plan',
      'removePlanGuard',
    );

    const confirmedStopCall = 'if err := cancelAdapterStopConfirmed(ctx, adapter, victim.Execution, victimTarget); err != nil {';
    const unsupportedException = 'if err := cancelAdapterBounded(ctx, adapter, victim.Execution, victimTarget); err != nil && !errors.Is(err, ErrUnsupported) {';
    assertUniqueAnchor(original, confirmedStopCall, 'restoreUnsupportedException');
    writeFileSync(managerPath, original.replace(confirmedStopCall, unsupportedException));
    const unsupportedTest = `${tests[1]}/unsupported`;
    const unsupportedPattern = `^${tests[1]}$/^unsupported$`;
    assertIntendedMutationFailure(
      runExactTests(fixture, unsupportedPattern),
      unsupportedTest,
      tests[1],
      'cancel stop confirmation assertion: unsupported cancellation was treated as confirmed',
      'restoreUnsupportedException',
    );
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
assert.ok(args.length === 0 || (args.length === 1 && args[0] === '--faults'), 'usage: node scripts/verify-preemption-stop-guards.mjs [--faults]');
if (args.length === 1) {
  runFaults();
  console.log('preemption stop guards fault verification passed');
} else {
  assertExecutedTests(runExactTests());
  console.log('preemption stop guards verification passed');
}
