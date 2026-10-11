import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const freezePath = path.join(root, '.unlazy/fleet-residency-v2/plan-relaunch-transport48-freeze.json');
const frozenPaths = [
  'internal/nodeagent/checkpoint_plan_rotation.go',
  'internal/nodeagent/checkpoint_plan_rotation_linux.go',
  'internal/nodeagent/checkpoint_plan_rotation_other.go',
  'internal/nodeagent/checkpoint_plan_rotation_test.go',
  'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
  'internal/nodeagent/checkpoint_lifecycle_broker.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_linux.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_other.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_test.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_linux_test.go',
  'internal/nodeagent/commands.go',
  'internal/nodeagent/commands_test.go',
  'internal/wsproto/messages.go',
  'internal/wsproto/messages_test.go',
  'cmd/checkpoint-lifecycle-broker/main.go',
  'deploy/checkpoint-lifecycle-broker.service',
  'scripts/verify-checkpoint-plan-relaunch.mjs',
].sort();
const argv = process.argv.slice(2);
const modes = new Set(['--mode=source-only', '--mode=authority', '--mode=reconcile', '--mode=cpu-sequence']);
let preservePrivateWorkspace = false;
if (argv.length !== 1 || !modes.has(argv[0])) {
  console.error('usage: node scripts/verify-checkpoint-plan-relaunch.mjs --mode=source-only|authority|reconcile|cpu-sequence');
  process.exit(2);
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, encoding: 'utf8', timeout: 1_000_000, maxBuffer: 8 * 1024 * 1024, ...options });
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0) {
    process.stderr.write(output);
    throw new Error(`${program} exited ${result.status ?? 'without a status'}`);
  }
  return output;
}

function exactInventory(output, expected) {
  const events = new Map(), malformed = [], rejected = [];
  for (const line of output.split(/\r?\n/)) {
    let match;
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      match = line.match(/^\s*=== RUN\s+(\S+)\s*$/);
      if (!match) malformed.push(line);
      else {
        const event = events.get(match[1]) ?? [];
        event.push('RUN'); events.set(match[1], event);
      }
    }
    if (/^\s*--- (PASS|SKIP|FAIL):/.test(line)) {
      match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
      if (!match) malformed.push(line);
      else {
        const event = events.get(match[2]) ?? [];
        event.push(match[1]); events.set(match[2], event);
        if (match[1] !== 'PASS') rejected.push(`${match[1]}:${match[2]}`);
      }
    }
  }
  const unexpected = [...events.keys()].filter((name) => !expected.includes(name));
  const missing = expected.filter((name) => JSON.stringify(events.get(name) ?? []) !== '["RUN","PASS"]');
  if (unexpected.length || missing.length || rejected.length || malformed.length) {
    throw new Error(`exact RUN/PASS inventory mismatch: unexpected=${unexpected}; missing-or-reordered=${missing}; rejected=${rejected}; malformed=${malformed}`);
  }
}

const descriptorGuardControlCases = [
  ['false_absent_no_writer', 0], ['false_unrelated_no_writer', 0], ['true_exact_fd10_writer', 0],
  ['false_fd10_writer', 151], ['false_unrelated_higher_writer', 195], ['false_absent_higher_writer', 195],
  ['true_missing_fd10', 150], ['true_unrelated_fd10', 152], ['true_exact_plus_extra_writer', 178],
];
const descriptorGuardControlTest = 'TestPlanBrokerCPUDescriptorGuardControls';
const descriptorGuardControlEventPrefix = '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__';

function classifyDescriptorGuardControlResult(result) {
  if (!result || result.error || result.status === null || result.status === undefined) {
    throw new Error('descriptor guard control has no confirmed bounded child status');
  }
  if (result.status !== 0) throw new Error('descriptor guard positive inventory did not exit zero');
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  exactInventory(output, [descriptorGuardControlTest]);
  const outputLines = output.split(/\r?\n/);
  let parentRunIndex = -1, parentPassIndex = -1;
  for (const [index, line] of outputLines.entries()) {
    let match;
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      match = line.match(/^\s*=== RUN\s+(\S+)\s*$/);
      if (match?.[1] === descriptorGuardControlTest) parentRunIndex = index;
    }
    if (/^\s*--- (PASS|SKIP|FAIL):/.test(line)) {
      match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
      if (match?.[1] === 'PASS' && match[2] === descriptorGuardControlTest) parentPassIndex = index;
    }
  }
  if (parentRunIndex < 0 || parentPassIndex <= parentRunIndex) {
    throw new Error('descriptor guard case completion has no closed parent RUN/PASS interval');
  }
  const observed = [];
  for (const [index, line] of outputLines.entries()) {
    if (line.startsWith('__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_') && !line.startsWith(descriptorGuardControlEventPrefix)) {
      throw new Error('descriptor guard event has an unknown marker');
    }
    if (!line.startsWith(descriptorGuardControlEventPrefix)) continue;
    const match = line.match(/^__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\t([a-z0-9_]+)\t(0|[1-9][0-9]{0,2})$/);
    if (!match) throw new Error('descriptor guard event has an unknown shape');
    if (index <= parentRunIndex || index >= parentPassIndex) {
      throw new Error('descriptor guard case completion falls outside its parent RUN/PASS interval');
    }
    observed.push([match[1], Number(match[2])]);
  }
  if (JSON.stringify(observed) !== JSON.stringify(descriptorGuardControlCases)) {
    throw new Error('descriptor guard actual case completion inventory is missing, extra, reordered, duplicated, or has a wrong finite status');
  }
  return { status: 0, testName: descriptorGuardControlTest, cases: observed };
}

function selfTestDescriptorGuardControlResult() {
  const lines = descriptorGuardControlCases.map(([name, status]) => `${descriptorGuardControlEventPrefix}\t${name}\t${status}`);
  const runLine = `=== RUN   ${descriptorGuardControlTest}`;
  const passLine = `--- PASS: ${descriptorGuardControlTest} (0.01s)`;
  const positive = `${runLine}\n${lines.join('\n')}\n${passLine}\nPASS\n`;
  const known = classifyDescriptorGuardControlResult({ error: null, status: 0, stdout: positive, stderr: '' });
  if (known.cases.length !== 9 || known.testName !== descriptorGuardControlTest) throw new Error('descriptor guard positive classifier control lost its exact nine-case inventory');
  const reject = (result, label) => {
    let failed = false;
    try { classifyDescriptorGuardControlResult(result); } catch { failed = true; }
    if (!failed) throw new Error(`descriptor guard result classifier accepted ${label}`);
  };
  reject({ error: null, status: 0, stdout: positive.replace(`${lines[0]}\n`, ''), stderr: '' }, 'missing case event');
  reject({ error: null, status: 0, stdout: positive.replace(`${lines[8]}\n`, `${lines[8]}\n${lines[4]}\n`), stderr: '' }, 'extra event');
  reject({ error: null, status: 0, stdout: positive.replace(`${lines[0]}\n${lines[1]}\n`, `${lines[1]}\n${lines[0]}\n`), stderr: '' }, 'reordered events');
  reject({ error: null, status: 0, stdout: positive.replace(`${lines[0]}\n`, `${lines[0]}\n${lines[0]}\n`), stderr: '' }, 'duplicate event');
  reject({ error: null, status: 0, stdout: positive.replace(`--- PASS: ${descriptorGuardControlTest}`, `--- SKIP: ${descriptorGuardControlTest}`), stderr: '' }, 'skipped parent test');
  reject({ error: null, status: 0, stdout: positive.replace(`--- PASS: ${descriptorGuardControlTest}`, `--- FAIL: ${descriptorGuardControlTest}`), stderr: '' }, 'failed parent test');
  reject({ error: null, status: 0, stdout: positive.replace(lines[3], `${descriptorGuardControlEventPrefix}\tfalse_fd10_write\t151`), stderr: '' }, 'wrong case name');
  reject({ error: null, status: 0, stdout: positive.replace(descriptorGuardControlEventPrefix, '__WRONG_DESCRIPTOR_EVENT__'), stderr: '' }, 'wrong marker');
  reject({ error: null, status: 0, stdout: positive.replace(lines[3], `${descriptorGuardControlEventPrefix}\tfalse_fd10_writer\t195`), stderr: '' }, 'wrong finite status');
  reject({ error: null, status: 0, stdout: positive.replace(`=== RUN   ${descriptorGuardControlTest}`, '=== RUN   TestOther'), stderr: '' }, 'wrong top-level test');
  reject({ error: null, status: 0, stdout: positive.replace(`=== RUN   ${descriptorGuardControlTest}\n`, `=== RUN   ${descriptorGuardControlTest}\n=== RUN   ${descriptorGuardControlTest}\n`), stderr: '' }, 'duplicate parent RUN');
  reject({ error: null, status: 0, stdout: `${lines.join('\n')}\n${runLine}\n${passLine}\nPASS\n`, stderr: '' }, 'all case markers before parent RUN');
  reject({ error: null, status: 0, stdout: `${runLine}\n${passLine}\n${lines.join('\n')}\nPASS\n`, stderr: '' }, 'all case markers after parent PASS');
  reject({ error: null, status: 0, stdout: `${lines[0]}\n${runLine}\n${lines.slice(1).join('\n')}\n${passLine}\nPASS\n`, stderr: '' }, 'single case marker crossing parent interval');
  reject({ error: null, status: 1, stdout: positive, stderr: '' }, 'nonzero child status');
  reject({ error: new Error('timeout'), status: null, stdout: positive, stderr: '' }, 'timeout without terminal status');
  reject({ error: null, status: null, stdout: positive, stderr: '' }, 'null child status');
  return true;
}

const inactiveWaitOwners = [
  'TestCheckpointPlanRelaunchCPULifecycleSequence',
  'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect',
];
const inactiveWaitCodes = new Set([
  'private_binding', 'show_unavailable', 'show_envelope', 'state_parse', 'empty_invocation', 'empty_control_group',
  'empty_invocation_control_group', 'pid_state_shape', 'nonzero_pid',
  'invocation_mismatch', 'unit_definition_missing', 'worker_state', 'jobs_unavailable', 'jobs_malformed',
  'pending_job', 'cgroup_unconfirmed', 'unavailable',
]);

function classifyInactiveWaitFailure(output, expected) {
  if (typeof output !== 'string' || !Array.isArray(expected) || expected.some((name) => typeof name !== 'string')) return 'inactive_wait=unavailable';
  const expectedOwners = inactiveWaitOwners.filter((name) => expected.includes(name));
  const runAt = new Map();
  const failAt = new Map();
  const failures = [];
  let malformedFailure = false;
  let malformedRun = false;
  const lifecycle = [];
  const markers = [];
  const lines = output.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const run = line.match(/^=== RUN   (\S+)$/);
      if (!run) { malformedRun = true; lifecycle.push({ kind: 'malformed', lineIndex }); }
      else {
        lifecycle.push({ kind: 'RUN', name: run[1], lineIndex });
        if (inactiveWaitOwners.includes(run[1])) runAt.set(run[1], [...(runAt.get(run[1]) ?? []), lineIndex]);
      }
    } else if (/^\s*===/.test(line)) {
      lifecycle.push({ kind: 'malformed', lineIndex });
    }
    if (/^\s*--- FAIL(?:\s|:)/.test(line)) {
      const match = line.match(/^--- FAIL: (\S+) \((?:\d+(?:\.\d+)?s)\)$/);
      if (!match) { malformedFailure = true; lifecycle.push({ kind: 'malformed', lineIndex }); }
      else {
        failures.push(match[1]);
        lifecycle.push({ kind: 'FAIL', name: match[1], lineIndex });
        if (inactiveWaitOwners.includes(match[1])) failAt.set(match[1], [...(failAt.get(match[1]) ?? []), lineIndex]);
      }
    } else if (/^\s*--- (?:PASS|SKIP)(?:\s|:)/.test(line)) {
      const match = line.match(/^--- (PASS|SKIP): (\S+) \((?:\d+(?:\.\d+)?s)\)$/);
      lifecycle.push(match ? { kind: match[1], name: match[2], lineIndex } : { kind: 'malformed', lineIndex });
    } else if (/^\s*(?:===|---)/.test(line) && !/^\s*=== RUN(?:\s|$)/.test(line)) {
      lifecycle.push({ kind: 'malformed', lineIndex });
    }
    if (line.includes('__PLAN_RELAUNCH_INACTIVE_WAIT__')) markers.push({ line, lineIndex });
  }
  const malformedLifecycle = lifecycle.some((event) => event.kind === 'malformed');
  if (malformedRun || malformedFailure || malformedLifecycle || failures.length === 0 || failures.some((name) => !expectedOwners.includes(name)) ||
      new Set(failures).size !== failures.length || markers.length !== failures.length) return 'inactive_wait=unavailable';
  const found = new Map();
  const markerAt = new Map();
  for (const marker of markers) {
    const match = marker.line.match(/^__PLAN_RELAUNCH_INACTIVE_WAIT__:([A-Za-z0-9_]+):([a-z_]+)$/);
    if (!match || !inactiveWaitOwners.includes(match[1]) || !expectedOwners.includes(match[1]) ||
        !failures.includes(match[1]) || !inactiveWaitCodes.has(match[2]) || found.has(match[1])) return 'inactive_wait=unavailable';
    found.set(match[1], match[2]);
    markerAt.set(match[1], marker.lineIndex);
  }
  if (found.size !== failures.length || failures.some((name) => {
    const starts = runAt.get(name) ?? [], ends = failAt.get(name) ?? [], markerIndex = markerAt.get(name);
    const interveningLifecycle = lifecycle.some((event) => event.lineIndex > starts[0] && event.lineIndex < ends[0]);
    const contradictoryOwnerCompletion = lifecycle.some((event) => event.name === name && (event.kind === 'PASS' || event.kind === 'SKIP'));
    return !found.has(name) || starts.length !== 1 || ends.length !== 1 ||
      !(starts[0] < markerIndex && markerIndex < ends[0]) ||
      interveningLifecycle || contradictoryOwnerCompletion;
  })) return 'inactive_wait=unavailable';
  return failures.map((name) => `${name}=${found.get(name)}`).join(';');
}

const failureStageOwners = new Set(inactiveWaitOwners);
const failureStages = new Set(['matrix_admission', 'matrix_case', 'matrix_reserve', 'parentdeath_setup', 'parentdeath_ready', 'parentdeath_signal', 'parentdeath_terminal', 'holder_acquire', 'cleanup', 'unavailable']);
const childPreReadyFailureReasons = new Set(['child_case_or_root', 'child_budget', 'child_unit', 'child_plan', 'child_launch', 'child_worker_pidfd', 'child_holder_handshake', 'child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply', 'child_phase_frame', 'child_transcript', 'child_helper_early_exit', 'child_holder_pre_spawn_binding', 'child_holder_pre_spawn_deadline', 'child_holder_root_metadata', 'child_holder_launch_current', 'child_holder_unit_current', 'child_holder_pipe_setup', 'child_holder_token_setup', 'child_holder_parent_pidfd', 'child_holder_root_handle', 'child_holder_spawn', 'child_holder_child_identity', 'child_holder_child_cgroup', 'child_holder_helper_read', 'child_holder_helper_shape', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape']);
const childCapOnlyFailureReasons = new Set(['child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape']);
const failureReasons = new Set(['deadline', 'identity', 'pipe_or_frame', 'unexpected_exit', 'unit_or_worker_state', 'descriptor_close', 'result_uncertain', 'unavailable', 'report_ready', 'report_metrics', 'report_result', 'report_pass', 'report_eof', ...childPreReadyFailureReasons]);
const watchdogReportReasons = new Set(['report_ready', 'report_metrics', 'report_result', 'report_pass', 'report_eof']);
const failureMatrixCases = new Set(['watchdog_native_expiry', 'watchdog_absolute_cap', 'startup_parentdeath', 'parentdeath_pre_ready_after_arm', 'parentdeath_import_boundary', 'parentdeath_constructor_boundary', 'parentdeath_method_boundary', 'parentdeath_held_idle', 'parentdeath_close_boundary', 'parentdeath_after_rearm']);
const maxFailureStageDiagnosticBytes = 512;

function classifyTypedFailureStage(output, expected) {
  const unavailable = 'failure_stage=unavailable';
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > maxFailureCaptureBytes ||
      !Array.isArray(expected) || expected.length === 0 || expected.length > 32 ||
      expected.some((name) => typeof name !== 'string' || !reviewedInventoryTestNames.has(name)) || new Set(expected).size !== expected.length) return unavailable;
  const expectedOwners = inactiveWaitOwners.filter((name) => expected.includes(name));
  if (expectedOwners.length === 0) return unavailable;
  const lifecycle = new Map();
  const markers = [];
  let active = null;
  const lines = output.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (Buffer.byteLength(line, 'utf8') > maxFailureLineBytes) return unavailable;
    if (/^\s*(?:===|---)/.test(line)) {
      const run = line.match(/^=== RUN   (Test[A-Za-z0-9_]+(?:\/[A-Za-z0-9_.-]+)*)$/);
      const outcome = line.match(/^--- (PASS|FAIL|SKIP): (Test[A-Za-z0-9_]+(?:\/[A-Za-z0-9_.-]+)*) \(([0-9]+(?:\.[0-9]+)?s)\)$/);
      if (run) {
        const owner = run[1];
        if (!expected.includes(owner) || active || lifecycle.has(owner)) return unavailable;
        active = { owner, start: lineIndex, end: null, outcome: null };
        lifecycle.set(owner, active);
      } else if (outcome) {
        if (!active || active.owner !== outcome[2] || active.outcome !== null) return unavailable;
        active.end = lineIndex;
        active.outcome = outcome[1];
        active = null;
      } else return unavailable;
    }
    if (line.includes('__PLAN_RELAUNCH_FAILURE_STAGE__')) markers.push({ line, lineIndex });
  }
  if (active || [...lifecycle.keys()].some((name) => !expected.includes(name))) return unavailable;
  const failures = expected.filter((name) => lifecycle.get(name)?.outcome === 'FAIL');
  if (!failures.length || lifecycle.size !== expected.length) return unavailable;
  const byOwner = new Map();
  for (const item of markers) {
    const match = item.line.match(/^__PLAN_RELAUNCH_FAILURE_STAGE__:([A-Za-z0-9_]+):([a-z_]+):([a-z_]+)(?::([a-z_]+))?(?::diag:([a-z_]+):([a-z_]+):(unavailable|exit_[0-9]{1,3}|signal_[0-9]{1,2}))?$/);
    if (!match) return unavailable;
    const [, owner, stage, reason, matrixCase, readReason, waitPhase, waitStatus] = match;
    if (!failureStageOwners.has(owner) || !expectedOwners.includes(owner) || !failures.includes(owner) ||
        !failureStages.has(stage) || !failureReasons.has(reason) || stage === 'unavailable' && reason !== 'unavailable') return unavailable;
    const ownerStage = owner === inactiveWaitOwners[0]
      ? ['matrix_admission', 'matrix_case', 'matrix_reserve', 'cleanup', 'unavailable'].includes(stage)
      : ['parentdeath_setup', 'parentdeath_ready', 'parentdeath_signal', 'parentdeath_terminal', 'holder_acquire', 'cleanup', 'unavailable'].includes(stage);
    if (!ownerStage) return unavailable;
    const lifecycleOwner = lifecycle.get(owner);
    if (!lifecycleOwner || !(lifecycleOwner.start < item.lineIndex && item.lineIndex < lifecycleOwner.end)) return unavailable;
    if (matrixCase !== undefined && (!failureMatrixCases.has(matrixCase) || stage !== 'matrix_case' || owner !== inactiveWaitOwners[0])) return unavailable;
    if (watchdogReportReasons.has(reason) && (stage !== 'matrix_case' || owner !== inactiveWaitOwners[0] || !['watchdog_native_expiry', 'watchdog_absolute_cap'].includes(matrixCase))) return unavailable;
    if (childPreReadyFailureReasons.has(reason) && (stage !== 'matrix_case' || owner !== inactiveWaitOwners[0] || !['watchdog_native_expiry', 'watchdog_absolute_cap'].includes(matrixCase))) return unavailable;
    if (childCapOnlyFailureReasons.has(reason) && matrixCase !== 'watchdog_absolute_cap') return unavailable;
    if ((readReason !== undefined || reason === 'child_holder_helper_read' && matrixCase === 'watchdog_native_expiry') &&
        (readReason === undefined || owner !== inactiveWaitOwners[0] || stage !== 'matrix_case' || reason !== 'child_holder_helper_read' || matrixCase !== 'watchdog_native_expiry' ||
          !['deadline', 'pipe_or_frame', 'unexpected_exit', 'unit_or_worker_state', 'descriptor_close', 'unavailable'].includes(readReason) ||
          !['pre_settled', 'post_settled', 'unavailable'].includes(waitPhase) ||
          waitPhase === 'unavailable' !== (waitStatus === 'unavailable'))) return unavailable;
    if (readReason !== undefined && waitStatus !== 'unavailable') {
      const status = waitStatus.match(/^(exit|signal)_([0-9]+)$/);
      if (!status || String(Number(status[2])) !== status[2] || status[1] === 'exit' && Number(status[2]) > 255 || status[1] === 'signal' && (Number(status[2]) < 1 || Number(status[2]) > 64)) return unavailable;
    }
    if (stage === 'matrix_case' && matrixCase === undefined && reason !== 'unavailable') return unavailable;
    if (stage !== 'matrix_case' && matrixCase !== undefined) return unavailable;
    const list = byOwner.get(owner) ?? [];
    if (list.length >= 2) return unavailable;
    list.push({ stage, reason, matrixCase, readDiagnostic: readReason === undefined ? undefined : { readReason, waitPhase, waitStatus }, lineIndex: item.lineIndex });
    byOwner.set(owner, list);
  }
  for (const owner of failures) {
    const list = byOwner.get(owner) ?? [];
    if (list.length === 0 || list.length === 2 && (list[0].stage === 'cleanup' || list[1].stage !== 'cleanup' || list[1].lineIndex <= list[0].lineIndex)) return unavailable;
  }
  if (markers.some(({ line }) => !line.startsWith('__PLAN_RELAUNCH_FAILURE_STAGE__:'))) return unavailable;
  const summary = failures.map((owner) => {
    const list = byOwner.get(owner);
    const primary = list[0];
    const base = `${owner}:${primary.stage}:${primary.reason}${primary.matrixCase ? `:${primary.matrixCase}` : ''}${primary.readDiagnostic ? `:read=${primary.readDiagnostic.readReason}:wait=${primary.readDiagnostic.waitPhase}:${primary.readDiagnostic.waitStatus}` : ''}`;
    return list.length === 2 ? `${base},cleanup:${list[1].reason}` : base;
  }).join(';');
  const diagnostic = `failure_stage=${summary}`;
  return Buffer.byteLength(diagnostic, 'utf8') <= maxFailureStageDiagnosticBytes ? diagnostic : unavailable;
}

function validatePreReadyFailureFrameSource(verifierSource, goSource) {
  const fail = (message) => { throw new Error(`pre-READY failure-frame source predicate: ${message}`); };
  const reasons = [
    'child_case_or_root', 'child_budget', 'child_unit', 'child_plan', 'child_launch', 'child_worker_pidfd',
    'child_holder_handshake', 'child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply',
    'child_phase_frame', 'child_transcript', 'child_helper_early_exit',
    'child_holder_pre_spawn_binding', 'child_holder_pre_spawn_deadline', 'child_holder_root_metadata', 'child_holder_launch_current',
    'child_holder_unit_current', 'child_holder_pipe_setup', 'child_holder_token_setup', 'child_holder_parent_pidfd',
    'child_holder_root_handle', 'child_holder_spawn', 'child_holder_child_identity', 'child_holder_child_cgroup',
    'child_holder_helper_read', 'child_holder_helper_shape', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read',
    'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send',
    'child_holder_cap_ref_read', 'child_holder_cap_ref_shape',
  ];
  const goReason = (reason) => ({
    child_worker_pidfd: 'planBrokerCPUReasonChildWorkerPIDFD',
    child_holder_parent_pidfd: 'planBrokerCPUReasonChildHolderParentPIDFD',
  }[reason] ?? `planBrokerCPUReason${reason.split('_').map((part) => part[0].toUpperCase() + part.slice(1)).join('')}`);
  for (const reason of reasons) if (!goSource.includes(`${goReason(reason)} planBrokerCPUFailureReason = "${reason}"`)) fail(`closed Go typed reason is missing: ${reason}`);
  const frameStart = goSource.indexOf('func planBrokerCPUPreReadyFailureReason(site planBrokerCPUPreReadyFailureSite) planBrokerCPUFailureReason {');
  const readerStart = goSource.indexOf('func (reader *planBrokerCPUControlReader) read(deadline time.Time) (string, error) {');
  if (frameStart < 0 || readerStart <= frameStart) fail('private frame helpers are missing or outside the existing bounded reader boundary');
  const frameHelpers = goSource.slice(frameStart, readerStart);
  const genericParser = uniqueSourceRegion(goSource, 'func planBrokerCPUParsePreReadyFailureFrame(record string, control planBrokerCPUHolderControl) (planBrokerCPUFailureReason, bool) {', '\nfunc planBrokerCPUWritePreReadyFailureFrame(');
  for (const required of [
    'func planBrokerCPUPreReadyFailureFrame(control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite) (string, bool)',
    'control != planBrokerCPUControlWatchdogNative && control != planBrokerCPUControlWatchdogCap',
    'if control != planBrokerCPUControlWatchdogCap { return "", false }',
    '"CONTROL_FAILURE\\t" + string(control) + "\\t" + string(site) + "\\n"',
    'if len(frame) > 192',
    'func planBrokerCPUParsePreReadyFailureFrame(record string, control planBrokerCPUHolderControl) (planBrokerCPUFailureReason, bool)',
    'strings.Split(record, "\\t")', 'len(fields) != 3', 'fields[0] != "CONTROL_FAILURE"', 'fields[1] != string(control)',
    'strings.ContainsAny(record, "\\r\\n")',
    'func planBrokerCPUWritePreReadyFailureFrame(writer io.Writer, control planBrokerCPUHolderControl, site planBrokerCPUPreReadyFailureSite) bool',
    'n, err := writer.Write([]byte(frame))', 'return err == nil && n == len(frame)',
    'func (write planBrokerCPUPreReadyWriteFunc) Write(p []byte) (int, error)',
  ]) if (!frameHelpers.includes(required)) fail(`private frame encoder/parser/writer lost a closed property: ${required}`);
  if (!genericParser.includes('len(fields) != 3') || !genericParser.includes('fields[1] != string(control)')) fail('private frame encoder/parser/writer lost a closed property: selected case comparison');
  const controls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(');
  for (const required of [
    'planBrokerCPUWritePreReadyFailureFrame(writer, testCase.control, site)', 'writes != 1',
    'strings.Count(frame, "\\t") != 2', 'len(frame) > 192', 'strings.Count(frame, "\\n") != 1',
    'planBrokerCPUParsePreReadyFailureFrame(strings.TrimSuffix(frame, "\\n"), testCase.control)',
    'planBrokerCPUFailureSiteCapHealthIdentity', 'planBrokerCPUFailureSiteCapHealthSend', 'planBrokerCPUFailureSiteCapHealthReply',
    'planBrokerCPUControlWatchdogNative, planBrokerCPUFailureSiteCapHealthIdentity',
    'planBrokerCPUControlStartupDeath, planBrokerCPUFailureSiteBudget',
    'return len(p)-1, nil', 'injected frame write error',
    'planBrokerCPUHolderControlReportMessageCount(planBrokerCPUControlWatchdogNative) != 3',
  ]) if (!controls.includes(required)) fail(`pure Go private-frame control is missing: ${required}`);
  const parent = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlParent(t *testing.T) {', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  const parsedCase = parent.indexOf('control, err := readPlanBrokerCPUHolderControlCase()');
  const invalidCase = parent.indexOf('t.Fatal("private holder control case is invalid")');
  const emitClosure = parent.indexOf('emitPreReadyFailure := func(site planBrokerCPUPreReadyFailureSite) {');
  const readyOutput = parent.indexOf('fmt.Printf("CONTROL_READY\\t%s\\t%s\\t%d\\t%d\\t%d\\t%d\\t%d\\n"');
  if (parsedCase < 0 || invalidCase <= parsedCase || emitClosure <= invalidCase || readyOutput <= emitClosure ||
      !parent.includes('watchdogFailure := control == planBrokerCPUControlWatchdogNative || control == planBrokerCPUControlWatchdogCap') ||
      !parent.includes('if watchdogFailure && !planBrokerCPUWritePreReadyFailureFrame(os.Stdout, control, site)')) fail('writer must be unreachable before case validation and must remain private, checked, single-write and watchdog-only');
  const branches = [
    ['CaseOrRoot', 'fixed holder control parent identity is invalid'],
    ['CaseOrRoot', 'fixed holder control root is not exact'],
    ['Budget', 'fixed holder control case has no finite deadline'],
    ['Unit', 'fixed holder control requires the original loaded active worker'],
    ['Plan', 'fixed holder control active plan is unavailable'],
    ['Launch', 'fixed holder control worker identity could not be captured'],
    ['WorkerPIDFD', 'fixed holder control worker pidfd could not be captured'],
    ['HolderHandshake', 'fixed holder control handshake failed'],
    ['CapHealthIdentity', 'fixed cap progress lost its bounded holder/phase identity'],
    ['CapHealthSend', 'fixed cap valid progress request failed'],
    ['CapHealthReply', 'fixed cap valid same-connection progress did not complete'],
    ['PhaseFrame', 'fixed control case/phase marker did not match its closed enum'],
    ['Transcript', 'fixed control transcript exceeds its independently derived frame/message budget'],
    ['HelperEarlyExit', 'controlled helper exited before its parent-death event'],
  ];
  for (const [site, fatalText] of branches) {
    if (site === 'HolderHandshake') {
      const exact = 'site := planBrokerCPUHolderBranchFailureSite(err, control)\n\t\tif diagnostic, ok := planBrokerCPUHolderReadDiagnosticOf(err); ok && control == planBrokerCPUControlWatchdogNative && site == planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) {\n\t\t\temitNativeHelperReadFailure(site, diagnostic)\n\t\t} else {\n\t\t\temitPreReadyFailure(site)\n\t\t}\n\t\tt.Fatal("fixed holder control handshake failed")';
      if (!parent.includes(exact)) fail(`missing, duplicated, or relocated elected emission before its unchanged fatal: ${site}/${fatalText}`);
      continue;
    }
    const call = site === 'HolderHandshake' ? 'emitPreReadyFailure(planBrokerCPUHolderBranchFailureSite(err, control))' : `emitPreReadyFailure(planBrokerCPUFailureSite${site})`;
    const occurrences = [];
    for (let at = parent.indexOf(call); at >= 0; at = parent.indexOf(call, at + call.length)) occurrences.push(at);
    const expectedCount = site === 'CaseOrRoot' ? 2 : 1;
    const adjacent = occurrences.some((callAt) => {
      const fatalAt = parent.indexOf(`t.Fatal("${fatalText}")`, callAt + call.length);
      return fatalAt >= callAt && /^[;\s]*$/.test(parent.slice(callAt + call.length, fatalAt));
    });
    if (occurrences.length !== expectedCount || !adjacent) fail(`missing, duplicated, or relocated elected emission before its unchanged fatal: ${site}/${fatalText}`);
  }
  const capStart = parent.indexOf('if control == planBrokerCPUControlWatchdogCap {');
  const capEnd = parent.indexOf('\n\tif control == planBrokerCPUControlCloseDeath {', capStart);
  const capBranch = capStart < 0 || capEnd <= capStart ? '' : parent.slice(capStart, capEnd);
  for (const site of ['CapHealthIdentity', 'CapHealthSend', 'CapHealthReply']) if (!capBranch.includes(`emitPreReadyFailure(planBrokerCPUFailureSite${site})`)) fail(`cap-only health site escaped its selected cap branch: ${site}`);
  const firstReadAt = parent.indexOf('first, err := stdoutReader.read(deadline)');
  const parseAt = parent.indexOf('planBrokerCPUParsePreReadyFailureFrame(first, control)', firstReadAt);
  const readyFieldsAt = parent.indexOf('fields := strings.Split(first, "\\t")', firstReadAt);
  const normalReadErrorAt = parent.indexOf('if err != nil {', firstReadAt);
  if (firstReadAt < 0 || parseAt <= firstReadAt || parseAt >= normalReadErrorAt || parseAt >= readyFieldsAt ||
      !parent.slice(firstReadAt, readyFieldsAt).includes('stdoutReader.messages == 1') ||
      !parent.slice(parseAt, readyFieldsAt).includes('return abortParent(failure(reason, errors.New("source-owned pre-READY child branch frame was observed")))')) fail('only the existing first bounded read may parse an exact selected failure frame before READY');
  if (parent.indexOf('stdoutReader.read(deadline)', firstReadAt + 1) < 0 || !parent.includes('control event is not its fixed case/phase') ||
      !parent.includes('if watchdogReport { reason = planBrokerCPUReasonReportReady }')) fail('invalid/missing failure frames must fall through to the original generic READY path');
  const reportCount = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderControlReportMessageCount(control planBrokerCPUHolderControl) int {', '\nfunc waitPlanBrokerCPUHolderTerminal(');
  if (!reportCount.includes('case planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap:\n\t\treturn 3')) fail('failure-only observation must not change the original three-record positive inventory');
  if (!goSource.includes('verifyPlanBrokerCPUFailureMarkerControls()') || !goSource.includes('planBrokerCPUParsePreReadyFailureFrame(first, control)')) fail('pre-fixture controls or first-read parser invocation are not source-bound');
  const formatter = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureMarker(owner string, err error) string {', '\nfunc planBrokerCPUFailureOfStage(');
  const markerControls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {');
  if (!formatter.includes('if (planBrokerCPUPreReadyFailureReasonCapOnly(failure.reason) || planBrokerCPUHolderBranchCapOnly(failure.reason)) && caseName != string(planBrokerCPUControlWatchdogCap)') ||
      !goSource.includes('func planBrokerCPUPreReadyFailureReasonCapOnly(reason planBrokerCPUFailureReason) bool {') ||
      !markerControls.includes('synthetic native cap-health reason') || !markerControls.includes('formatter accepted a cap-only health reason')) fail('Go formatter/control must reject cap-only child reasons on native watchdog cases');
  return true;
}

function validateNativeHelperReadDiagnosticSource(verifierSource, goSource) {
  const fail = (message) => { throw new Error(`native helper-read diagnostic source predicate: ${message}`); };
  const state = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderReadDiagnosticForState(', '\nfunc planBrokerCPUHolderReadDiagnosticValid(');
  const valid = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderReadDiagnosticValid(', '\nfunc planBrokerCPUHolderReadDiagnosticBeforeAbort(');
  const before = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderReadDiagnosticBeforeAbort(', '\nfunc planBrokerCPUHolderReadDiagnosticAfterAbort(');
  const after = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderReadDiagnosticAfterAbort(', '\nfunc planBrokerCPUJoinPrimaryAbortForHelperRead(');
  const capture = uniqueSourceRegion(goSource, 'func planBrokerCPUJoinPrimaryAbortForHelperRead(', '\nfunc planBrokerCPUParseHolderReadWaitStatus(');
  const frame = uniqueSourceRegion(goSource, 'func planBrokerCPUNativeHelperReadFailureFrame(', '\nfunc planBrokerCPUParseNativeHelperReadFailureFrame(');
  const parser = uniqueSourceRegion(goSource, 'func planBrokerCPUParseNativeHelperReadFailureFrame(', '\nfunc planBrokerCPUWriteNativeHelperReadFailureFrame(');
  const writer = uniqueSourceRegion(goSource, 'func planBrokerCPUWriteNativeHelperReadFailureFrame(', '\nfunc planBrokerCPUHolderReadDiagnosticOf(');
  const attach = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureAttachHolderReadDiagnostic(', '\nconst planBrokerCPUFailureMarkerControlAssertion');
  const control = uniqueSourceRegion(goSource, 'func startPlanBrokerCPUUnitHolderControl(', 'func readPlanBrokerCPUHolderControlCase(');
  const parent = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlParent(t *testing.T) {', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  const caseGo = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlCase(', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  const formatter = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureMarker(owner string, err error) string {', '\nfunc planBrokerCPUFailureOfStage(');
  const controls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(');
  const matrix = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlMatrix(', '\nfunc startPlanBrokerCPUUnitHolderMode(');
  const matrixWrapper = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderControlMatrixFailure(', '\nfunc planBrokerCPUCleanupFailure(');
  for (const required of [
    'validReadReason', 'settledBeforeAbort && !settledAfterAbort', 'if !settledAfterAbort { return diagnostic, true }',
    'statusCode > 255', 'statusCode > 64', 'diagnostic.waitPhase = "pre_settled"', 'diagnostic.waitPhase = "post_settled"',
  ]) if (!state.includes(required)) fail(`state validator is missing ${required}`);
  if (!state.includes('readReason: readReason') || !valid.includes('diagnostic.waitPhase == "unavailable" && diagnostic.waitStatus == "unavailable"') ||
      !valid.includes('return ok && parsed == diagnostic') || !before.includes('case <-holder.waitDone: return true; default: return false') ||
      after.indexOf('case <-holder.waitDone:') < 0 || after.indexOf('holder.cmd.ProcessState.Sys()') <= after.indexOf('case <-holder.waitDone:') ||
      after.includes('cmd.Wait()') || after.includes('PidfdSendSignal') || after.includes('signal.setitimer')) fail('waitDone-gated status inspection or explicit unavailable state is missing or gained new effects');
  const preAt = capture.indexOf('readReason := planBrokerCPUHolderReadDiagnosticReason(readErr)');
  const snapshotAt = capture.indexOf('settledBeforeAbort := planBrokerCPUHolderReadDiagnosticBeforeAbort(holder)');
  const abortAt = capture.indexOf('joined := planBrokerCPUJoinPrimaryAbort(reason, primary, holder)');
  const settleAt = capture.indexOf('planBrokerCPUHolderReadDiagnosticAfterAbort(holder, readReason, settledBeforeAbort)');
  if (preAt < 0 || snapshotAt <= preAt || abortAt <= snapshotAt || settleAt <= abortAt ||
      (capture.match(/planBrokerCPUJoinPrimaryAbort\(/g) ?? []).length !== 1 ||
      !capture.includes('return &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: diagnostic, cause: joined}')) fail('read reason and pre-abort wait snapshot must precede exactly one unchanged primary-first abort; status settlement follows it');
  if (!control.includes('primary := planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)') ||
      !control.includes('if control == planBrokerCPUControlWatchdogNative { return nil, "", planBrokerCPUJoinPrimaryAbortForHelperRead(planBrokerCPUReasonPipe, err, primary, holder) }') ||
      !control.includes('return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, primary, holder)')) fail('only the original native first-read failure must capture diagnostics while cap continues through the untouched generic abort path');
  const errStart = control.indexOf('if err != nil {\n\t\t\tprimary := planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)');
  const errEnd = control.indexOf('\n\t\tif frame != "CONTROL_READY', errStart);
  const readBranch = errStart < 0 || errEnd <= errStart ? '' : control.slice(errStart, errEnd);
  if ((readBranch.match(/planBrokerCPUJoinPrimaryAbortForHelperRead\(/g) ?? []).length !== 1 ||
      (readBranch.match(/planBrokerCPUJoinPrimaryAbort\(/g) ?? []).length !== 1 ||
      readBranch.indexOf('planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)') > readBranch.indexOf('planBrokerCPUJoinPrimaryAbortForHelperRead(')) fail('first-read branch must retain the same typed primary and exactly one native diagnostic abort path');
  if (!frame.includes('control != planBrokerCPUControlWatchdogNative') || !frame.includes('site != planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead)') ||
      !frame.includes('diagnostic.readReason') || !frame.includes('diagnostic.waitPhase') || !frame.includes('diagnostic.waitStatus') || !frame.includes('if len(frame) > 192')) fail('failure frame must carry only the exact closed native read reason and qualified wait status within the existing frame cap');
  if (!parser.includes('len(fields) != 6') || !parser.includes('fields[1] != string(control)') ||
      !parser.includes('fields[2] != string(planBrokerCPUReasonChildHolderHelperRead)') || !parser.includes('planBrokerCPUHolderReadDiagnosticValid(diagnostic)') ||
      !parser.includes('strings.TrimSuffix(frame, "\\n") == record') || !writer.includes('n, err := writer.Write([]byte(frame))') ||
      !writer.includes('return err == nil && n == len(frame)')) fail('native diagnostic parser/writer must be exact, closed, one-record and single checked write');
  const emitStart = parent.indexOf('emitNativeHelperReadFailure := func(');
  const startError = parent.indexOf('site := planBrokerCPUHolderBranchFailureSite(err, control)', emitStart);
  if (emitStart < 0 || startError <= emitStart || !parent.slice(startError, parent.indexOf('defer func()', startError)).includes('planBrokerCPUHolderReadDiagnosticOf(err)') ||
      !parent.slice(startError, parent.indexOf('defer func()', startError)).includes('control == planBrokerCPUControlWatchdogNative') ||
      !parent.slice(startError, parent.indexOf('defer func()', startError)).includes('emitNativeHelperReadFailure(site, diagnostic)')) fail('diagnostic frame emission must be restricted to the exact native helper-read site and share its one failure write');
  const caseRead = caseGo.indexOf('first, err := stdoutReader.read(deadline)');
  const diagnosticParse = caseGo.indexOf('planBrokerCPUParseNativeHelperReadFailureFrame(first, control)', caseRead);
  const attachAt = caseGo.indexOf('planBrokerCPUFailureAttachHolderReadDiagnostic(primary, diagnostic)', diagnosticParse);
  const abortAtCase = caseGo.indexOf('return abortParent(primary)', attachAt);
  const genericParse = caseGo.indexOf('planBrokerCPUParsePreReadyFailureFrame(first, control)', caseRead);
  if (caseRead < 0 || diagnosticParse <= caseRead || attachAt <= diagnosticParse || abortAtCase <= attachAt || genericParse <= abortAtCase ||
      !caseGo.slice(caseRead, genericParse).includes('control == planBrokerCPUControlWatchdogNative')) fail('native read diagnostics must be parsed, attached to the exact typed helper-read failure, and primary-first aborted before generic cases');
  if (!attach.includes('failure.stage != planBrokerCPUStageMatrixCase') || !attach.includes('failure.reason != planBrokerCPUReasonChildHolderHelperRead') ||
      !attach.includes('failure.caseName != string(planBrokerCPUControlWatchdogNative)') || !attach.includes('failure.helperReadDiagnostic = &diagnostic') ||
      !formatter.includes('failure.helperReadDiagnostic == nil') || !formatter.includes('failure.helperReadDiagnostic != nil') || !formatter.includes('marker += ":diag:"')) fail('closed diagnostic must bind only the selected native typed marker and preserve its original failure class');
  const diagnosticBlock = 'diagnostic := *inner.helperReadDiagnostic\n\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)';
  if (!matrix.includes('return planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err)') ||
      !matrixWrapper.includes('fmt.Errorf("fixed holder control %s failed: %w", caseName, err)') ||
      !matrixWrapper.includes('inner := planBrokerCPUFirstFailure(err, false)') ||
      !matrixWrapper.includes('outer := planBrokerCPUFirstFailure(wrapped, false)') ||
      !matrixWrapper.includes('outer != wrappedFailure') ||
      !matrixWrapper.includes('inner.stage != planBrokerCPUStageMatrixCase') ||
      !matrixWrapper.includes('inner.reason != planBrokerCPUReasonChildHolderHelperRead') ||
      !matrixWrapper.includes('inner.caseName != string(planBrokerCPUControlWatchdogNative)') ||
      !matrixWrapper.includes('wrappedFailure.stage != inner.stage || wrappedFailure.reason != inner.reason || wrappedFailure.caseName != inner.caseName') ||
      !matrixWrapper.includes('!planBrokerCPUHolderReadDiagnosticValid(*inner.helperReadDiagnostic)') ||
      !matrixWrapper.includes(diagnosticBlock) ||
      !controls.includes('actual matrix wrapper did not value-copy the selected native diagnostic') ||
      !controls.includes('native diagnostic behind different selected primary') ||
      !controls.includes('cleanup-only diagnostic') || !controls.includes('foreign cap case') ||
      !controls.includes('foreign primary reason') || !controls.includes('foreign primary stage') ||
      !controls.includes('invalid diagnostic')) fail('actual matrix wrapper must value-copy only a validated selected native primary diagnostic through the real selector and formatter');
  for (const required of [
    'preDiagnostic, preOK := planBrokerCPUHolderReadDiagnosticForState("deadline", true, true, "exit", 17)',
    'postDiagnostic, postOK := planBrokerCPUHolderReadDiagnosticForState("pipe_or_frame", false, true, "signal", 9)',
    'unsettledDiagnostic, unsettledOK := planBrokerCPUHolderReadDiagnosticForState("unexpected_exit", false, false, "signal", 9)',
    'synthetic helper-read failure', 'native helper-read diagnostic did not reach its exact bounded typed failure marker',
  ]) if (!controls.includes(required)) fail(`known-positive or negative diagnostic control is missing ${required}`);
  const classifier = uniqueSourceRegion(verifierSource, 'function classifyTypedFailureStage(output, expected) {', '\nfunction validateTypedFailureStageSource(');
  if (!classifier.includes('diag:([a-z_]+):([a-z_]+):(unavailable|exit_[0-9]{1,3}|signal_[0-9]{1,2})') ||
      !classifier.includes("reason === 'child_holder_helper_read' && matrixCase === 'watchdog_native_expiry'") ||
      !classifier.includes('primary.readDiagnostic.readReason') || !classifier.includes('wait=${primary.readDiagnostic.waitPhase}:${primary.readDiagnostic.waitStatus}')) fail('Node reducer must require and surface native read/wait fields in the bounded typed failure summary');
  const emitOrder = uniqueSourceRegion(verifierSource, 'function executeInventory(', '\nfunction withPrivateBinary(');
  if (!emitOrder.includes('${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\\n') ||
      emitOrder.includes('${diagnostic}; ${siteDiagnostic}; ${stageDiagnostic}\\n')) fail('bounded stage/read evidence must appear before potentially lengthy test-site diagnostics');
  return true;
}

function validatePureDiagnosticControlSource(verifierSource, goSource) {
  const testName = 'TestPlanBrokerCPUFailureMarkerControlsPure';
  const marker = '__PLAN_RELAUNCH_PURE_DIAGNOSTIC_CONTROL_FAILURE__';
  const assertion = 'actual matrix wrapper did not value-copy the selected native diagnostic while preserving primary-first causes';
  const diagnosticBlock = '\tdiagnostic := *inner.helperReadDiagnostic\n\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)';
  const controls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence');
  const matrix = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlMatrix(', '\nfunc startPlanBrokerCPUUnitHolderMode(');
  const checkedFailureHelper = `checkedDiagnosticFailure := func(label string, err error) (*planBrokerCPUFailure, error) {
		failure, ok := err.(*planBrokerCPUFailure)
		if err == nil || !ok || failure == nil { return nil, fmt.Errorf("%s constructor returned an unexpected failure type", label) }
		return failure, nil
	}`;
  if (!controls.includes(checkedFailureHelper)) throw new Error('diagnostic controls must check the concrete result of their actual error-returning constructors without panics or silent skips');
  const positiveConstructor = 'inner, innerErr := checkedDiagnosticFailure("native helper-read primary", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: parsedDiagnostic, cause: diagnosticPrimaryCause}))';
  const positiveAt = controls.indexOf(positiveConstructor);
  const positiveErrorAt = controls.indexOf('if innerErr != nil { return innerErr }', positiveAt);
  const positiveDiagnosticAt = controls.indexOf('inner.helperReadDiagnostic', positiveErrorAt);
  if (positiveAt < 0 || positiveErrorAt <= positiveAt || positiveDiagnosticAt <= positiveErrorAt ||
      !controls.includes('failure, ok := err.(*planBrokerCPUFailure)') ||
      !controls.includes('if err == nil || !ok || failure == nil { return nil, fmt.Errorf("%s constructor returned an unexpected failure type", label) }')) {
    throw new Error('positive diagnostic primary must be concretely checked before diagnostic attachment or alias assertions');
  }
  if (controls.split('planBrokerCPUHolderControlMatrixFailure(string(planBrokerCPUControlWatchdogNative),').length !== 3 ||
      matrix.split('planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err)').length !== 2 ||
      controls.includes('planBrokerCPUHolderControlMatrixFailure(planBrokerCPUControlWatchdogNative,') ||
      matrix.includes('planBrokerCPUHolderControlMatrixFailure(testCase.control, err)')) {
    throw new Error('all named closed controls must convert explicitly at the string matrix wrapper boundary');
  }
  for (const [name, constructor] of [
    ['foreign cap case', 'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogCap), errors.New("foreign cap case"))'],
    ['foreign primary reason', 'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonPipe, string(planBrokerCPUControlWatchdogNative), errors.New("foreign primary reason"))'],
    ['foreign primary stage', 'planBrokerCPUFailureAt(planBrokerCPUStageMatrixReserve, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("foreign primary stage"))'],
    ['invalid diagnostic', 'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("invalid diagnostic"))'],
    ['cleanup-only diagnostic', 'planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, errors.New("cleanup-only diagnostic"))'],
    ['nested native diagnostic', 'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), errors.New("nested native diagnostic"))'],
  ]) {
    const local = name === 'foreign cap case' ? 'foreignCase' : name === 'foreign primary reason' ? 'foreignReason' : name === 'foreign primary stage' ? 'foreignStage' : name === 'invalid diagnostic' ? 'invalidDiagnostic' : name === 'cleanup-only diagnostic' ? 'cleanupOnly' : 'nestedNative';
    const errLocal = `${local}Err`;
    const call = `${local}, ${errLocal} := checkedDiagnosticFailure("${name}", ${constructor})`;
    if (!controls.includes(call) || !controls.includes(`if ${errLocal} != nil { return ${errLocal} }`) ||
        controls.split(`${local}.helperReadDiagnostic =`).length !== 2) {
      throw new Error(`diagnostic negative ${name} must use its actual constructor, check its concrete selection, and retain its assertion`);
    }
  }
  const pureTest = uniqueSourceRegion(goSource, `func ${testName}(t *testing.T) {`, '\nconst planBrokerCPUDescriptorGuardControlAssertion');
  const expectedPureTest = `func ${testName}(t *testing.T) {
	if err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {
		t.Fatalf("%s: %v", planBrokerCPUFailureMarkerControlAssertion, err)
	}
}
`;
  if (pureTest !== expectedPureTest || !goSource.includes(`const planBrokerCPUFailureMarkerControlAssertion = "${marker}"`)) {
    throw new Error('pure diagnostic controls must be a standalone exact test that calls the existing in-memory controls and reports their original error');
  }
  const modes = uniqueSourceRegion(verifierSource, 'function withPrivateBinary(mode) {', '\nconst recoveryPolicyTests = [');
  const reconcileAt = modes.indexOf("} else if (mode === '--mode=reconcile') {");
  const cpuAt = modes.indexOf("} else {\n      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'", reconcileAt);
  const reconcileEnd = modes.indexOf("} else {\n      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'", reconcileAt + 8);
  const cpuEnd = modes.indexOf('\n    }\n  } finally {', cpuAt);
  const reconcile = reconcileAt < 0 || reconcileEnd <= reconcileAt ? '' : modes.slice(reconcileAt, reconcileEnd);
  const cpu = cpuAt < 0 || cpuEnd <= cpuAt ? '' : modes.slice(cpuAt, cpuEnd);
  const positiveCall = `executeInventory(binary, ['${testName}'], 60, false);`;
  const fixtureInventory = 'const output = executeInventory(binary, selected, 240, true);';
  for (const [mode, branch] of [['reconcile', reconcile], ['cpu-sequence', cpu]]) {
    const compileAt = branch.indexOf('const binary = compileLinuxBinary(');
    const positiveAt = branch.indexOf(positiveCall);
    const mutantCall = `verifyCompiledHolderDiagnosticMutants(temp, '${mode}');`;
    const mutantAt = branch.indexOf(mutantCall);
    const fixtureAt = branch.indexOf(fixtureInventory);
    const selectedAt = branch.indexOf('const selected = [');
    const selectedEnd = branch.indexOf('];', selectedAt);
    const selected = selectedAt < 0 || selectedEnd <= selectedAt ? '' : branch.slice(selectedAt, selectedEnd + 2);
    if (compileAt < 0 || positiveAt <= compileAt || mutantAt <= positiveAt || fixtureAt <= mutantAt ||
        branch.split(positiveCall).length !== 2 || branch.split(mutantCall).length !== 2 ||
        selected.includes(testName)) {
      throw new Error(`pure diagnostic controls must run positive-first and both negatives before ${mode} fixture inventory with optIn=false`);
    }
  }
  const expectedFailure = `${marker}: ${assertion}`;
  const mutantRunner = uniqueSourceRegion(verifierSource, 'function verifyCompiledHolderDiagnosticMutants(temp, mode) {', '\nfunction verifyCompiledDescriptorGuardMutants(temp, mode) {');
  const expectedMutantRunner = `function verifyCompiledHolderDiagnosticMutants(temp, mode) {
  if (mode !== 'reconcile' && mode !== 'cpu-sequence') throw new Error('holder diagnostic mutants require one original CPU mode');
  const source = 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go';
  const testName = '${testName}';
  const expectedFailure = '${expectedFailure}';
  const diagnosticBlock = '\\tdiagnostic := *inner.helperReadDiagnostic\\n\\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)';
  compileBehavioralMutant(
    temp, \`holder-diagnostic-omission-\${mode}\`, source, [[diagnosticBlock, '\\t// omitted diagnostic attachment by compiled control']],
    '', testName, expectedFailure,
    'checkpoint_plan_broker_cpu', false,
  );
  compileBehavioralMutant(
    temp, \`holder-diagnostic-alias-\${mode}\`, source, [[diagnosticBlock, '\\twrappedFailure.helperReadDiagnostic = inner.helperReadDiagnostic']],
    '', testName, expectedFailure,
    'checkpoint_plan_broker_cpu', false,
  );
}
`;
  if (mutantRunner !== expectedMutantRunner ||
      !verifierSource.includes('executeExpectedFailureInventory(binary, testName, expectedFailure, optIn, cleanupEvidence)') ||
      !verifierSource.includes('if (result.status !== 1) throw new Error')) {
    throw new Error('compiled pure controls must replace the complete diagnostic block with compile-valid omission and pointer-alias mutants through the bounded exact expected-failure runner with optIn=false');
  }
  return true;
}

function validateTypedFailureStageSource(verifierSource, goSource) {
  validateHolderBranchAnnotationSource(goSource);
  validatePreReadyFailureFrameSource(verifierSource, goSource);
  validateNativeHelperReadDiagnosticSource(verifierSource, goSource);
  validatePureDiagnosticControlSource(verifierSource, goSource);
  const goOwnerNames = [
    'TestCheckpointPlanRelaunchCPULifecycleSequence',
    'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect',
  ];
  if (!goSource.includes('type planBrokerCPUFailureStage string') || !goSource.includes('type planBrokerCPUFailureReason string') ||
      !goSource.includes('type planBrokerCPUFailure struct {') || !goSource.includes('func (failure *planBrokerCPUFailure) Unwrap() error') ||
      !goSource.includes('type planBrokerCPUFixedMessageFailure struct { message string; cause error }') ||
      !goSource.includes('func planBrokerCPUFailureAt(') || !goSource.includes('func planBrokerCPUFailureMarker(owner string, err error) string') ||
      !goSource.includes('if !caseStage || !known') || !goSource.includes('len(marker) > 192') ||
      !goSource.includes('planBrokerCPUFailureOrigin(reason, err)') ||
      !goSource.includes('if existing.reason != "" { reason = existing.reason }') ||
      !goSource.includes('planBrokerCPUStageMatrixReserve, planBrokerCPUReasonDeadline') ||
      !goSource.includes('if !validOwner { return "__PLAN_RELAUNCH_FAILURE_STAGE__:unavailable:unavailable:unavailable" }') ||
      !goSource.includes('type planBrokerCPUFailureEmission struct {') ||
      !goSource.includes('func planBrokerCPUFailureMarkers(budget *planBrokerCPUFailureEmission, owner string, err error) []string') ||
      !goSource.includes('if !budget.primaryEmitted') || !goSource.includes('if !budget.cleanupEmitted') ||
      !goSource.includes('budget.primaryEmitted = true') || !goSource.includes('budget.cleanupEmitted = true') ||
      !goSource.includes('if len(markers) > 2') ||
      !goSource.includes('func planBrokerCPUJoinPrimaryAbort(reason planBrokerCPUFailureReason, primary error, holder *planBrokerCPUUnitHolder) error') ||
      !goSource.includes('func planBrokerCPUAbortCleanup(holder *planBrokerCPUUnitHolder) error')) throw new Error('Go typed diagnostics must retain fixed enums, bounded owner output, and a shared emission budget');
  const failureAt = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureAt(', '\nfunc planBrokerCPUCleanupFailure(');
  const markerGo = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureMarker(owner string, err error) string {', '\nfunc planBrokerCPUFailureOfStage(');
  if (!failureAt.includes('if stage == planBrokerCPUStageMatrixCase && caseName == "" { caseName = existing.caseName }') ||
      failureAt.includes('if caseName == "" { caseName = existing.caseName }')) throw new Error('matrix case context may only be inherited by a matrix_case wrapper; cleanup wrappers must not acquire a phantom case name');
  const matrixGo = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlMatrix(', '\nfunc startPlanBrokerCPUUnitHolderMode(');
  const caseGo = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlCase(', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  const reportReasonNames = ['Ready', 'Metrics', 'Result', 'Pass', 'EOF'];
  const reportReasonSnippets = [
    'if err != nil {\n\t\treason := planBrokerCPUReasonPipe\n\t\tif watchdogReport { reason = planBrokerCPUReasonReportReady }\n\t\treturn abortParent(failure(reason, err))\n\t}',
    '} else if len(fields) != 8 || fields[0] != "CONTROL_READY" || fields[1] != string(control) || fields[2] != wantPhase {\n\t\treason := planBrokerCPUReasonPipe\n\t\tif watchdogReport { reason = planBrokerCPUReasonReportReady }\n\t\treturn abortParent(failure(reason, errors.New("control event is not its fixed case/phase")))\n\t}',
    'if bytesErr != nil || messagesErr != nil || frameErr != nil || transcriptBytes < 1 || transcriptBytes > 1024 || transcriptMessages != expectedMessagesBeforeDeath || maximumFrame < 1 || maximumFrame > 192 {\n\t\treason := planBrokerCPUReasonPipe\n\t\tif watchdogReport { reason = planBrokerCPUReasonReportMetrics }\n\t\tmetricFailure := error(errors.New("control event transcript metrics violate fixed bounds"))\n\t\tif bytesErr != nil || messagesErr != nil || frameErr != nil { metricFailure = errors.Join(metricFailure, bytesErr, messagesErr, frameErr) }\n\t\treturn abortParent(failure(reason, metricFailure))\n\t}',
    'if bytesErr != nil || messagesErr != nil || frameErr != nil { metricFailure = errors.Join(metricFailure, bytesErr, messagesErr, frameErr) }',
    'if readErr != nil { resultFailure = errors.Join(resultFailure, readErr) }',
    'if tailErr != nil { passFailure = errors.Join(passFailure, tailErr) }',
    'failure(planBrokerCPUReasonReportResult, resultFailure)',
    'failure(planBrokerCPUReasonReportPass, passFailure)',
    'requireReportEOF(deadline, planBrokerCPUReasonReportEOF)',
  ];
  const reportOriginValid = reportReasonNames.every((name) => goSource.includes(`planBrokerCPUReasonReport${name} planBrokerCPUFailureReason = "report_${name.toLowerCase()}"`));
  const reportOriginProblems = [
    !reportOriginValid && 'missing reason enum',
    ...reportReasonSnippets.map((snippet, index) => !caseGo.includes(snippet) && `missing branch ${index}`),
    ...reportReasonNames.map((name) => !markerGo.includes(`failure.reason == planBrokerCPUReasonReport${name}`) && `missing formatter ${name}`),
    (caseGo.match(/if watchdogReport \{ reason = planBrokerCPUReasonReportReady \}/g) ?? []).length !== 2 && 'READY assignment cardinality',
    (caseGo.match(/if watchdogReport \{ reason = planBrokerCPUReasonReportMetrics \}/g) ?? []).length !== 1 && 'metrics assignment cardinality',
    !caseGo.includes('watchdogReport := control == planBrokerCPUControlWatchdogNative || control == planBrokerCPUControlWatchdogCap') && 'watchdog selector',
    !markerGo.includes('reportReason := failure.reason == planBrokerCPUReasonReportReady || failure.reason == planBrokerCPUReasonReportMetrics || failure.reason == planBrokerCPUReasonReportResult || failure.reason == planBrokerCPUReasonReportPass || failure.reason == planBrokerCPUReasonReportEOF') && 'formatter reason set',
    !markerGo.includes('if reportReason && (owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" || !caseStage || (caseName != string(planBrokerCPUControlWatchdogNative) && caseName != string(planBrokerCPUControlWatchdogCap)))') && 'formatter case boundary',
    !caseGo.includes('if err := requireReportEOF(deadline, planBrokerCPUReasonPipe); err != nil') && 'other-case EOF reason',
    !caseGo.includes('second != "CONTROL_RESULT\\t"+string(control)+"\\twatchdog_sigalrm"') && 'exact RESULT comparison',
    !caseGo.includes('tail != "PASS"') && 'exact PASS comparison',
    !caseGo.includes('waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, deadline)') && 'helper terminal proof',
    !caseGo.includes('planBrokerCPULaunchStillCurrent(paths, launch)') && 'identity proof',
    !caseGo.includes('unitAfter.MainPID != unitBefore.MainPID') && 'post-state proof',
    !caseGo.includes('os.SameFile(rootInfo, currentRoot)') && 'root identity proof',
  ].filter(Boolean);
  const watchdogBranchAt = caseGo.indexOf('if watchdogReport {\n\t\tsecond, readErr := stdoutReader.read(deadline)');
  const orderedWatchdogChecks = [
    caseGo.indexOf('helperIdentity, helperIdentityErr := capturePlanBrokerCPUProcessIdentity(helperPID)'),
    watchdogBranchAt,
    caseGo.indexOf('second, readErr := stdoutReader.read(deadline)', watchdogBranchAt),
    caseGo.indexOf('tail, tailErr := stdoutReader.read(deadline)', watchdogBranchAt),
    caseGo.indexOf('if waitErr := waitUntil(deadline); waitErr != nil', watchdogBranchAt),
    caseGo.indexOf('waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, deadline)', watchdogBranchAt),
    caseGo.indexOf('requireReportEOF(deadline, planBrokerCPUReasonReportEOF)', watchdogBranchAt),
    caseGo.indexOf('planBrokerCPULaunchStillCurrent(paths, launch)', watchdogBranchAt),
    caseGo.indexOf('afterCtx, cancelAfter := context.WithDeadline(context.Background(), deadline)', watchdogBranchAt),
    caseGo.indexOf('os.SameFile(rootInfo, currentRoot)', watchdogBranchAt),
  ];
  if (watchdogBranchAt < 0 || orderedWatchdogChecks.some((at, i) => at < 0 || i > 0 && at <= orderedWatchdogChecks[i - 1])) reportOriginProblems.push('watchdog report/Wait/terminal/EOF/post-state order');
  if (reportOriginProblems.length) throw new Error(`watchdog report origins must remain exact, case-restricted, cause-preserving, and downstream proofs unchanged: ${reportOriginProblems.join(', ')}`);
  const acquireGo = uniqueSourceRegion(goSource, 'func startPlanBrokerCPUUnitHolderMode(', '\nfunc planBrokerCPUHolderEOFParentAliveOutcome(');
  const parentGo = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(');
  const survivorTypeStart = goSource.indexOf('func (failure *planBrokerCPUSurvivorPredicateFailure) Error() string {');
  const survivorTypeEnd = goSource.indexOf('func (failure *planBrokerCPUSurvivorPredicateFailure) Unwrap() error', survivorTypeStart);
  const survivorType = survivorTypeStart < 0 || survivorTypeEnd <= survivorTypeStart ? '' : goSource.slice(survivorTypeStart, survivorTypeEnd);
  const acquisitionJoin = uniqueSourceRegion(goSource, 'func planBrokerCPUJoinPrimaryAbort(', '\nfunc planBrokerCPUAbortCleanup(');
  const acquisitionGo = uniqueSourceRegion(goSource, 'func startPlanBrokerCPUUnitHolderMode(', '\nfunc planBrokerCPUHolderEOFParentAliveOutcome(');
  const releaseGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) release() error {', '\nfunc (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(');
  const eofGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(', '\nfunc (holder *planBrokerCPUUnitHolder) abort(');
  const abortGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) abort() error {', '\nfunc (holder *planBrokerCPUUnitHolder) closeFiles(');
  const closeFilesGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) closeFiles() error {', '\nfunc planBrokerCPUHolderIdentityCurrent(');
  const sendGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) send(frame string) error {', '\nfunc (holder *planBrokerCPUUnitHolder) readFrame(');
  const readFrameWrapperGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) readFrame(timeout time.Duration) (string, error) {', '\nfunc (holder *planBrokerCPUUnitHolder) readFrameUntil(');
  const readFrameGo = uniqueSourceRegion(goSource, 'func (holder *planBrokerCPUUnitHolder) readFrameUntil(', '\nfunc (holder *planBrokerCPUUnitHolder) health(');
  const matrixWrapperGo = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderControlMatrixFailure(', '\nfunc planBrokerCPUCleanupFailure(');
  const parentCleanupStop = parentGo.slice(parentGo.indexOf('stopExactParent = func() error {'), parentGo.indexOf('childHandles := make([]struct {'));
  const survivorRewrite = parentGo.slice(parentGo.indexOf('if survivorObserved && result != nil'), parentGo.indexOf('\n\t}()', parentGo.indexOf('if survivorObserved && result != nil')));
  if (!matrixGo.includes('runPlanBrokerCPUHolderControlCase(paths, root, rootInfo, launch, testCase.control, caseDeadline)') ||
      !matrixGo.includes('return planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err)') ||
      !matrixWrapperGo.includes('fmt.Errorf("fixed holder control %s failed: %w", caseName, err)') ||
      !caseGo.includes('planBrokerCPUFailureOrigin(reason, err)') ||
      !caseGo.includes('planBrokerCPUReasonDeadline') || !caseGo.includes('planBrokerCPUReasonIdentity') ||
      !caseGo.includes('planBrokerCPUReasonPipe') || !caseGo.includes('planBrokerCPUReasonExit') ||
      !caseGo.includes('planBrokerCPUReasonUnit') || !caseGo.includes('planBrokerCPUReasonClose') ||
      !acquireGo.includes('origin := func(reason planBrokerCPUFailureReason, err error) (*planBrokerCPUUnitHolder, error)') ||
      !acquireGo.includes('planBrokerCPUReasonDeadline') || !acquireGo.includes('planBrokerCPUReasonIdentity') ||
      !acquireGo.includes('planBrokerCPUReasonPipe') || !acquireGo.includes('planBrokerCPUReasonExit') ||
      !acquireGo.includes('planBrokerCPUReasonUnit') || !acquireGo.includes('planBrokerCPUReasonClose') ||
      parentGo.includes('failureStage') || parentGo.includes('failureReason') || parentGo.includes('primaryFailure') ||
      !parentGo.includes('return failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonPipe, errors.New("parent-death report pipe could not be created"))') ||
      !parentGo.includes('return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonPipe, errors.New("parent helper did not emit one bounded identity frame; preserving fixture"))') ||
      !parentCleanupStop.includes('failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonIdentity') ||
      !parentCleanupStop.includes('return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonIdentity, errors.New("parent helper was not live immediately before induced death; preserving fixture"))') ||
      !parentCleanupStop.includes('failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonExit') ||
      !parentCleanupStop.includes('failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline') ||
      !parentCleanupStop.includes('return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline, errors.New("exact parent helper did not exit within its fixed bound; preserving fixture"))') ||
      !parentGo.includes('return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonExit, errors.New("a direct child survived exact parent death and required pidfd-only emergency cleanup"))') ||
      !parentGo.includes('planBrokerCPUFailureAt(planBrokerCPUStageCleanup,') ||
      !parentGo.includes('planBrokerCPUCleanupFailure(planBrokerCPUReasonClose,') ||
      !survivorRewrite.includes('&planBrokerCPUSurvivorPredicateFailure{err: result}') ||
      !survivorRewrite.includes('result.Error() == "a direct child survived exact parent death and required pidfd-only emergency cleanup"') ||
      !survivorType.includes('"__PLAN_RELAUNCH_PARENT_DEATH_SURVIVOR_ASSERTED__ __PLAN_RELAUNCH_PARENT_DEATH_PIDFD_CLEANUP_PROVED__ direct child survived exact parent death and required pidfd-only cleanup"') ||
      !goSource.includes('func (failure *planBrokerCPUSurvivorPredicateFailure) Unwrap() error { return failure.err }') ||
      acquisitionJoin.indexOf('primaryFailure := planBrokerCPUFailureOrigin(reason, primary)') < 0 ||
      acquisitionJoin.indexOf('primaryFailure := planBrokerCPUFailureOrigin(reason, primary)') >= acquisitionJoin.indexOf('abortErr := holder.abort()') ||
      !acquisitionJoin.includes('cleanupFailure := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(abortErr), abortErr)') ||
      !acquisitionJoin.includes('return errors.Join(primaryFailure, cleanupFailure)') ||
      (acquisitionGo.match(/planBrokerCPUJoinPrimaryAbort\(/g) ?? []).length !== 8 || acquisitionGo.includes('errors.Join(errors.New(') ||
      !releaseGo.includes('finish := func(err error) error { holder.releaseErr = err; return holder.releaseErr }') ||
      releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, err)') ||
      !releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder release lacks its exact held state"))') ||
      !releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, errors.New("unit holder identity changed before normal release"))') ||
      !releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline,') ||
      !releaseGo.includes('return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder did not reap within the fixed release deadline")))') ||
      !releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonExit,') ||
      !releaseGo.includes('return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder normal release did not produce one zero-exit Wait")))') ||
      !releaseGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe,') ||
      !releaseGo.includes('if err := holder.requireStatusEOFUntil(deadline); err != nil { return finish(err) }') ||
      !releaseGo.includes('return finish(holder.closeFiles())') ||
      !eofGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline,') ||
      !eofGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe,') ||
      !eofGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonClose,') ||
      !eofGo.includes('return planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder status stream did not reach exact EOF within the shared release deadline"))') ||
      !eofGo.includes('return planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe, errors.New("unit holder status stream contained a trailing or duplicate response"))') ||
      !eofGo.includes('return planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, errors.New("unit holder status EOF descriptor reported an invalid event"))') ||
      (abortGo.match(/planBrokerCPUFailureOrigin\(planBrokerCPUReasonClose, err\)/g) ?? []).length < 3 ||
      !closeFilesGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonClose,') ||
      !closeFilesGo.includes('if err := unix.Close(holder.childPIDFD); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, &planBrokerCPUFixedMessageFailure{message: "unit holder pidfd close failed", cause: err}))') ||
      !sendGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe,') || !sendGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit,') ||
      !readFrameGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline,') || !readFrameGo.includes('if !deadline.After(time.Now()) { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response budget or state is invalid")) }') ||
      !readFrameWrapperGo.includes('if timeout <= 0 { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response deadline is invalid")) }') ||
      !readFrameGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonExit,') || !readFrameGo.includes('planBrokerCPUFailureOrigin(planBrokerCPUReasonPipe,'))
    throw new Error('matrix, acquisition, direct parent return origins, and survivor typed wrapper must remain wired');
  const lifecycleGo = uniqueSourceRegion(goSource, 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {', '\nfunc TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {');
  const crashGo = uniqueSourceRegion(goSource, 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {', '\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {');
  const lifecycleOwnerFailure = lifecycleGo.slice(lifecycleGo.indexOf('if err := runPlanBrokerCPUHolderControlMatrix('), lifecycleGo.indexOf('t.Fatalf("fixed ten-case unit holder control matrix'));
  const crashOwnerFailure = crashGo.slice(crashGo.indexOf('if err := runPlanBrokerCPUParentDeathOracle('), crashGo.indexOf('t.Fatalf("fixed parent-death EOF oracle failed'));
  const lifecycleCleanup = lifecycleGo.slice(lifecycleGo.indexOf('cleanup := func() error {'), lifecycleGo.indexOf('\n\tdefer func() {', lifecycleGo.indexOf('cleanup := func() error {')));
  const crashCleanup = crashGo.slice(crashGo.indexOf('cleanup := func() error {'), crashGo.indexOf('\n\tdefer func() {', crashGo.indexOf('cleanup := func() error {')));
  const ownerBudgetWired = (owner) => {
    const body = owner === goOwnerNames[0] ? lifecycleGo : crashGo;
    const emits = [...body.matchAll(/planBrokerCPUFailureMarkers\(([^,]+),/g)].map((match) => match[1]);
    return body.includes('var failureEmission planBrokerCPUFailureEmission') && emits.length >= 2 && emits.every((budget) => budget === '&failureEmission') &&
      !body.includes('planBrokerCPUFailureMarker("' + owner + '"');
  };
  if (!lifecycleGo.includes('if err := runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt); err != nil {') ||
      !lifecycleOwnerFailure.includes('planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPULifecycleSequence"') ||
      !crashGo.includes('if err := runPlanBrokerCPUParentDeathOracle(workerExecutable, paths, rootInfo, uint32(gid)); err != nil {') ||
      !crashOwnerFailure.includes('planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect"') ||
      !goOwnerNames.every((owner) => goSource.includes(`planBrokerCPUFailureMarkers(&failureEmission, "${owner}"`)) ||
      !ownerBudgetWired(goOwnerNames[0]) || !ownerBudgetWired(goOwnerNames[1]) ||
      !lifecycleCleanup.includes('planBrokerCPUCleanupFailure(') || !crashCleanup.includes('planBrokerCPUCleanupFailure(') ||
      !lifecycleCleanup.includes('planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("transient unit does not join an exact held fixture launch; preserving private fixture"))') ||
      !crashCleanup.includes('if err := stopPlanBrokerCPUUnrelatedChild(unrelated); err != nil {\n\t\t\t\tresult = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, err))') ||
      !lifecycleCleanup.includes('errors.Join(cleanupErr, planBrokerCPUAbortCleanup(holder))') ||
      !crashCleanup.includes('errors.Join(result, planBrokerCPUAbortCleanup(holder))') ||
      !lifecycleGo.includes('planBrokerCPUFailureAt(planBrokerCPUStageCleanup,') ||
      !crashGo.includes('planBrokerCPUFailureAt(planBrokerCPUStageCleanup,')) throw new Error('owner-wide emission budget and real cleanup-origin markers must be wired at their actual fixture/oracle boundaries');
  const classifier = uniqueSourceRegion(verifierSource, 'function classifyTypedFailureStage(output, expected) {', '\nfunction validateTypedFailureStageSource(');
  if (!verifierSource.includes("const watchdogReportReasons = new Set(['report_ready', 'report_metrics', 'report_result', 'report_pass', 'report_eof']);")) throw new Error('typed failure-stage classifier is missing its closed report-reason set');
  if (!verifierSource.includes("const childPreReadyFailureReasons = new Set(['child_case_or_root', 'child_budget', 'child_unit', 'child_plan', 'child_launch', 'child_worker_pidfd', 'child_holder_handshake', 'child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply', 'child_phase_frame', 'child_transcript', 'child_helper_early_exit', 'child_holder_pre_spawn_binding', 'child_holder_pre_spawn_deadline', 'child_holder_root_metadata', 'child_holder_launch_current', 'child_holder_unit_current', 'child_holder_pipe_setup', 'child_holder_token_setup', 'child_holder_parent_pidfd', 'child_holder_root_handle', 'child_holder_spawn', 'child_holder_child_identity', 'child_holder_child_cgroup', 'child_holder_helper_read', 'child_holder_helper_shape', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape']);")) throw new Error('typed failure-stage classifier is missing its exact closed pre-READY child-site reason set');
  if (!verifierSource.includes("const childCapOnlyFailureReasons = new Set(['child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape']);") || !classifier.includes("if (childCapOnlyFailureReasons.has(reason) && matrixCase !== 'watchdog_absolute_cap') return unavailable;")) throw new Error('typed failure-stage reducer is missing its cap-only case gate');
  if (!classifier.includes("if (childPreReadyFailureReasons.has(reason) && (stage !== 'matrix_case' || owner !== inactiveWaitOwners[0] || !['watchdog_native_expiry', 'watchdog_absolute_cap'].includes(matrixCase))) return unavailable;")) throw new Error('typed failure-stage reducer is missing the selected watchdog owner/case gate for child branch reasons');
  for (const required of [
    'maxFailureCaptureBytes', 'maxFailureLineBytes', 'maxFailureStageDiagnosticBytes',
    "return Buffer.byteLength(diagnostic, 'utf8') <= maxFailureStageDiagnosticBytes ? diagnostic : unavailable;",
    "if (watchdogReportReasons.has(reason) && (stage !== 'matrix_case' || owner !== inactiveWaitOwners[0] || !['watchdog_native_expiry', 'watchdog_absolute_cap'].includes(matrixCase))) return unavailable;",
    'const expectedOwners = inactiveWaitOwners.filter((name) => expected.includes(name));',
    "line.match(/^__PLAN_RELAUNCH_FAILURE_STAGE__:", 'failureStages.has(stage)', 'failureReasons.has(reason)',
    'lifecycleOwner.start < item.lineIndex && item.lineIndex < lifecycleOwner.end',
    'list.length >= 2', 'list[0].stage === \'cleanup\'', "list[1].stage !== 'cleanup'", 'return unavailable',
  ]) if (!classifier.includes(required)) throw new Error(`typed failure-stage reducer is missing ${required}`);
  const inventory = uniqueSourceRegion(verifierSource, 'function executeInventory(', '\nfunction withPrivateBinary(');
  const branchStart = inventory.indexOf('if (result.status !== 0)');
  const branchEnd = inventory.indexOf('\n  try { exactInventory', branchStart);
  const branch = branchStart < 0 || branchEnd <= branchStart ? '' : inventory.slice(branchStart, branchEnd);
  const opted = branch.slice(branch.indexOf('if (optIn) {'), branch.indexOf('\n    }\n    process.stderr.write(output);'));
  if ((opted.match(/classifyTypedFailureStage\(output, expected\)/g) ?? []).length !== 1 ||
      !opted.includes('${stageDiagnostic}') || opted.includes('process.stderr.write(output)')) throw new Error('failure-only execution must consume and print the bounded stage reducer exactly once without forwarding raw output');
  return true;
}

function validateHolderBranchAnnotationSource(goSource) {
  const fail = (message) => { throw new Error(`holder-branch source predicate: ${message}`); };
  const mode = uniqueSourceRegion(goSource, 'func startPlanBrokerCPUUnitHolderMode(', '\nfunc (holder *planBrokerCPUUnitHolder) send(');
  const control = uniqueSourceRegion(goSource, 'func startPlanBrokerCPUUnitHolderControl(', '\nfunc startPlanBrokerCPUUnitHolderMode(');
  const parent = uniqueSourceRegion(goSource, 'func runPlanBrokerCPUHolderControlParent(t *testing.T) {', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  const join = uniqueSourceRegion(goSource, 'func planBrokerCPUJoinPrimaryAbort(', '\nfunc planBrokerCPUAbortCleanup(');
  const selector = uniqueSourceRegion(goSource, 'func planBrokerCPUHolderBranchFailureSite(', '\nfunc planBrokerCPUPreReadyFailureReasonCapOnly(');
  const encoder = uniqueSourceRegion(goSource, 'func planBrokerCPUPreReadyFailureFrame(', '\nfunc planBrokerCPUParsePreReadyFailureFrame(');
  const parser = uniqueSourceRegion(goSource, 'func planBrokerCPUParsePreReadyFailureFrame(', '\nfunc planBrokerCPUWritePreReadyFailureFrame(');
  const marker = uniqueSourceRegion(goSource, 'func planBrokerCPUFailureMarker(owner string, err error) string {', '\nfunc planBrokerCPUFailureOfStage(');
  const classes = [
    'child_holder_pre_spawn_binding', 'child_holder_pre_spawn_deadline', 'child_holder_root_metadata',
    'child_holder_launch_current', 'child_holder_unit_current', 'child_holder_pipe_setup',
    'child_holder_token_setup', 'child_holder_parent_pidfd', 'child_holder_root_handle',
    'child_holder_spawn', 'child_holder_child_identity', 'child_holder_child_cgroup',
    'child_holder_helper_read', 'child_holder_helper_shape', 'child_holder_cap_guard_send',
    'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata',
    'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape',
  ];
  for (const className of classes) if (!goSource.includes(`= "${className}"`)) fail(`closed typed reason is missing ${className}`);
  const modePredicates = [
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderPreSpawnBinding,',
    'originBranch(planBrokerCPUReasonDeadline, planBrokerCPUReasonChildHolderPreSpawnDeadline,',
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootMetadata,',
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderLaunchCurrent, err)',
    'originBranch(planBrokerCPUReasonUnit, planBrokerCPUReasonChildHolderUnitCurrent, primary)',
    'originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err)',
    'originBranch(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderTokenSetup, err)',
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderParentPIDFD, err)',
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootHandle, err)',
    'originBranch(planBrokerCPUReasonExit, planBrokerCPUReasonChildHolderSpawn, err)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderChildIdentity, cause)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderChildCgroup, cause)',
  ];
  for (const predicate of modePredicates) if (!mode.includes(predicate)) fail(`actual Mode return boundary is unannotated or misclassified: ${predicate}`);
  const originBranchDefinition = 'originBranch := func(reason planBrokerCPUFailureReason, class planBrokerCPUFailureReason, err error) (*planBrokerCPUUnitHolder, error) { return origin(reason, planBrokerCPUHolderBranchAt(class, err)) }';
  if (mode.split(originBranchDefinition).length !== 2 || mode.indexOf(originBranchDefinition) > mode.indexOf('if maxHealth != 27')) fail('actual originBranch definition must wrap the original cause before its actual Mode return sites');
  if ((mode.match(/originBranch\(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderPipeSetup, err\)/g) ?? []).length !== 5 ||
      (mode.match(/originBranch\(planBrokerCPUReasonPipe, planBrokerCPUReasonChildHolderTokenSetup, err\)/g) ?? []).length !== 1 ||
      (mode.match(/originBranch\(planBrokerCPUReasonClose, planBrokerCPUReasonChildHolderTokenSetup, err\)/g) ?? []).length !== 1 ||
      (mode.match(/planBrokerCPUReasonChildHolderParentPIDFD/g) ?? []).length !== 2 ||
      (mode.match(/planBrokerCPUReasonChildHolderRootHandle/g) ?? []).length !== 2) fail('shared pipe/token/pidfd/root descriptor classes do not cover each exact setup return site');
  const controlPredicates = [
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperShape, errors.New(',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardSend, err)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardRead, readyErr)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapGuardShape, errors.New(',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRootMetadata, errors.New(',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapAcquireSend, err)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRefRead, refErr)',
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRefShape, errors.New(',
  ];
  for (const predicate of controlPredicates) if (!control.includes(predicate)) fail(`actual control return boundary is unannotated or misclassified: ${predicate}`);
  if (!control.includes('primary := planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperRead, err)') ||
      !control.includes('if control == planBrokerCPUControlWatchdogNative { return nil, "", planBrokerCPUJoinPrimaryAbortForHelperRead(planBrokerCPUReasonPipe, err, primary, holder) }') ||
      !control.includes('return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, primary, holder)') ||
      !control.includes('if frame != "CONTROL_READY\\t"+string(control)+"\\t"+target')) fail('first helper read and exact shape must remain distinct with original read cause retained');
  const helperReadEmission = 'if diagnostic, ok := planBrokerCPUHolderReadDiagnosticOf(err); ok && control == planBrokerCPUControlWatchdogNative && site == planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) {\n\t\t\temitNativeHelperReadFailure(site, diagnostic)\n\t\t} else {\n\t\t\temitPreReadyFailure(site)\n\t\t}\n\t\tt.Fatal("fixed holder control handshake failed")';
  if (!parent.includes('site := planBrokerCPUHolderBranchFailureSite(err, control)\n\t\t' + helperReadEmission) ||
      !parent.includes('emitPreReadyFailure(site)')) fail('parent must emit the selected typed class or the exact native diagnostic before its unchanged fatal');
  const primaryAt = join.indexOf('primaryFailure := planBrokerCPUFailureOrigin(reason, primary)');
  const abortAt = join.indexOf('abortErr := holder.abort()');
  const cleanupAt = join.indexOf('cleanupFailure := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(abortErr), abortErr)');
  const orderedJoinAt = join.indexOf('return errors.Join(primaryFailure, cleanupFailure)');
  if (primaryAt < 0 || abortAt <= primaryAt || cleanupAt <= abortAt || orderedJoinAt <= cleanupAt || join.includes('return errors.Join(cleanupFailure, primaryFailure)')) fail('actual planBrokerCPUJoinPrimaryAbort must preserve primary-before-cleanup order');
  if (!goSource.includes('type planBrokerCPUHolderBranch struct { class planBrokerCPUFailureReason; cause error }') ||
      !goSource.includes('func (branch *planBrokerCPUHolderBranch) Error() string { return branch.cause.Error() }') ||
      !goSource.includes('func (branch *planBrokerCPUHolderBranch) Unwrap() error { return branch.cause }') ||
      !goSource.includes('if cause == nil { return nil }') || !goSource.includes('errors.As(err, &branch)')) fail('typed wrapper must preserve cause, delegate Error, support errors.As and leave nil unannotated');
  const controls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(');
  for (const required of [
    'branchClasses := []planBrokerCPUFailureReason{', 'errors.As(annotated, &exact)', 'errors.Is(annotated, primaryCause)',
    'direct := errors.Join(annotated, cleanupAnnotated)', 'errors.Is(direct, primaryCause)', 'errors.Is(direct, cleanupCause)',
    'errors.As(direct, &exact)', 'exact != annotated', 'planBrokerCPUHolderBranchClass(direct) != class',
    'joined := errors.Join(wrapped, errors.Join(errors.New("nested cleanup context"), cleanup))',
    'errors.Is(joined, primaryCause)', 'errors.Is(joined, cleanupCause)', 'errors.As(joined, &exact)',
    'planBrokerCPUHolderBranchClass(joined) != class', 'native watchdog accepted a cap-only holder branch frame',
    'formatter accepted a cap-only holder branch',
  ]) if (!controls.includes(required)) fail(`pure source-bound Go branch control is missing ${required}`);
  if (!controls.includes('cleanupClass := planBrokerCPUReasonChildHolderPipeSetup') ||
      !controls.includes('if class == planBrokerCPUReasonChildHolderPipeSetup { cleanupClass = planBrokerCPUReasonChildHolderTokenSetup }') ||
      !controls.includes('if cleanupClass == class { return errors.New("primary and cleanup holder annotations reused one class") }')) fail('primary and cleanup holder annotations must use distinct valid classes');
  if (mode.includes('err.Error()') || control.includes('err.Error()') || !goSource.includes('func planBrokerCPUHolderBranchReasonAllowed(reason planBrokerCPUFailureReason) bool {')) fail('branch selection must use only closed typed classes, never error text');
  if (!selector.includes('if !planBrokerCPUHolderBranchReasonAllowed(class) || (planBrokerCPUHolderBranchCapOnly(class) && control != planBrokerCPUControlWatchdogCap) { return planBrokerCPUFailureSiteHolderHandshake }')) fail('actual selector must reject cap-only holder classes on native watchdog cases');
  if (!encoder.includes('if planBrokerCPUHolderBranchCapOnly(planBrokerCPUFailureReason(site)) && control != planBrokerCPUControlWatchdogCap { return "", false }')) fail('actual pre-READY encoder must reject cap-only holder classes on native watchdog cases');
  if (!parser.includes('if _, ok := planBrokerCPUPreReadyFailureFrame(control, site); !ok { return "", false }')) fail('actual parser must consume the selected encoder guard for the parsed site');
  if (!marker.includes('(planBrokerCPUPreReadyFailureReasonAllowed(failure.reason) || planBrokerCPUHolderBranchReasonAllowed(failure.reason)) &&') ||
      !marker.includes('if (planBrokerCPUPreReadyFailureReasonCapOnly(failure.reason) || planBrokerCPUHolderBranchCapOnly(failure.reason)) && caseName != string(planBrokerCPUControlWatchdogCap) {') ||
      !controls.includes('planBrokerCPUParsePreReadyFailureFrame("CONTROL_FAILURE\\t"+string(planBrokerCPUControlWatchdogNative)+"\\t"+string(class), planBrokerCPUControlWatchdogNative)')) fail('closed branch reasons must bind the exact watchdog owner/case and reject cap-only native parsing');
  return true;
}

function validateFailureMarkerControlSource(goSource) {
  const controls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(');
  const parserControls = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUTestInventoryParserControls() error {', '\nfunc verifyPlanBrokerCPUStoppedSampleControls() error {');
  const lifecycle = uniqueSourceRegion(goSource, 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {', '\nfunc TestCheckpointPlanRelaunchCPUNodeClient(');
  const invalidOwnerExpected = 'invalidOwnerWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + invalidOwner + ":unavailable:unavailable"';
  if (!controls.includes(invalidOwnerExpected)) throw new Error('pure Go marker control source predicate: invalid-owner expected marker must use the selected owner');
  const required = [
    'planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, primaryCause)',
    'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonUnavailable, string(planBrokerCPUControlWatchdogCap), primaryOrigin)',
    'planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, cleanupCause)',
    'joined := errors.Join(primary, fmt.Errorf("nested cleanup: %w", cleanup))',
    'if !errors.Is(joined, primaryCause) || !errors.Is(joined, cleanupCause) {',
    'errors.Is(joined, primaryCause)', 'errors.Is(joined, cleanupCause)',
    'first := planBrokerCPUFirstFailure(joined, false)', 'firstCleanup := planBrokerCPUFirstFailure(joined, true)',
    'first != primary', 'firstCleanup != cleanup', 'firstCleanup.caseName != ""',
    '"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:deadline:" + string(planBrokerCPUControlWatchdogCap)',
    '"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:descriptor_close',
    'planBrokerCPUFailureMarkers(budget, owner, joined)',
    'planBrokerCPUFailureMarkers(budget, owner, joined); len(repeated) != 0',
    'cleanupFromMatrix := planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", primary)',
    'errors.Is(cleanupFromMatrix, primaryCause)',
    'planBrokerCPUFirstFailure(cleanupFromMatrix, false); firstMatrixPrimary != primary',
    'firstMatrixCleanup.reason != planBrokerCPUReasonDeadline', 'firstMatrixCleanup.caseName != ""',
    'if marker := planBrokerCPUFailureMarker(owner, cleanupFromMatrix); marker != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {',
    'cleanupViaHelper := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(primary), primary)',
    'secondaryCause := errors.New("secondary joined cause")',
    'nestedMatrix := errors.Join(fmt.Errorf("wrapped matrix cause: %w", primary), secondaryCause)',
    'nestedCleanup := planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUncertain, "", nestedMatrix)',
    '!errors.Is(nestedCleanup, primaryCause) || !errors.Is(nestedCleanup, secondaryCause)',
    'planBrokerCPUFirstFailure(nestedCleanup, false); firstNestedPrimary != primary',
    'if firstNestedCleanup := planBrokerCPUFirstFailure(nestedCleanup, true); firstNestedCleanup != nestedCleanup || firstNestedCleanup.reason != planBrokerCPUReasonDeadline || firstNestedCleanup.caseName != "" || planBrokerCPUFailureMarker(owner, nestedCleanup) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {',
    'reversed := errors.Join(cleanup, fmt.Errorf("nested primary: %w", primary))',
    'planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, owner, reversed)',
    'reversedWant := []string{\n\t\t"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable",\n\t\t"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:descriptor_close",\n\t}',
    'strings.Join(reversedMarkers, "\\x00") != strings.Join(reversedWant, "\\x00")',
    '!errors.Is(reversed, primaryCause) || !errors.Is(reversed, cleanupCause)',
    'reversedFirst := planBrokerCPUFirstFailure(reversed, false)',
    'reversedFirst.stage != "" || reversedFirst.reason != planBrokerCPUReasonClose',
    'reversedFirst.caseName != "" || planBrokerCPUFailureReasonOf(reversed) != planBrokerCPUReasonClose',
    'cleanupOnlyMarkers := planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, owner, cleanup)',
    'cleanupOnlyWant := []string{', 'strings.Join(cleanupOnlyMarkers, "\\x00") != strings.Join(cleanupOnlyWant, "\\x00")',
    'planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonDeadline, "foreign_case", primaryOrigin)',
    'invalidWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"',
    'marker != invalidWant || strings.Contains(marker, "foreign_case")',
    'foreignWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:unavailable:unavailable:unavailable"',
    'planBrokerCPUFailureMarker("unexpected-owner", primary)', 'marker != foreignWant',
    'reportReasons := []planBrokerCPUFailureReason{planBrokerCPUReasonReportReady, planBrokerCPUReasonReportMetrics, planBrokerCPUReasonReportResult, planBrokerCPUReasonReportPass, planBrokerCPUReasonReportEOF}',
    'for _, control := range []planBrokerCPUHolderControl{planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap}',
    'planBrokerCPUFailureOrigin(reason, cause)', 'errors.Is(failure, cause)',
    'report observation reason escaped its lifecycle watchdog case boundary',
    'if invalid.reason == planBrokerCPUReasonReportEOF && invalid.err.Error() == "crash owner report reason" { invalidOwner = "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect" }',
    'if marker := planBrokerCPUFailureMarker(invalidOwner, invalid); marker != invalidOwnerWant {',
  ];
  if (required.some((needle) => !controls.includes(needle)) ||
      !parserControls.startsWith('func verifyPlanBrokerCPUTestInventoryParserControls() error {\n\tif err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {') ||
      lifecycle.indexOf('verifyPlanBrokerCPUTestInventoryParserControls()') < 0 ||
      lifecycle.indexOf('verifyPlanBrokerCPUTestInventoryParserControls()') > lifecycle.indexOf('newPlanBrokerCPUFixtureRoot()') ||
      /\b(?:exec\.Command|systemd-run|newPlanBrokerCPUFixtureRoot|user\.Lookup|unix\.Pidfd)\b/.test(controls)) {
    throw new Error('actual pure Go marker controls must cover the cap primary, first-origin identity, cleanup, exact two-marker budget, and fail-closed adversaries before fixture work');
  }
  return true;
}

function selfTestFailureMarkerControlSource(goSource) {
  validateFailureMarkerControlSource(goSource);
  const reject = (mutant, label) => {
    let rejected = false;
    try { validateFailureMarkerControlSource(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`failure marker source predicate accepted ${label} mutant`);
  };
  const replaceOnce = (source, before, after, label) => {
    if (source.split(before).length !== 2) throw new Error(`failure marker mutation anchor is not unique: ${label}`);
    return source.replace(before, after);
  };
  const parserRegion = uniqueSourceRegion(goSource, 'func verifyPlanBrokerCPUTestInventoryParserControls() error {', '\nfunc verifyPlanBrokerCPUStoppedSampleControls() error {');
  const parserInvocationMutant = replaceOnce(parserRegion, 'if err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {', 'if err := nil; err != nil {', 'invocation');
  reject(goSource.replace(parserRegion, parserInvocationMutant), 'removed pre-fixture invocation');
  reject(replaceOnce(goSource, 'if !errors.Is(joined, primaryCause) || !errors.Is(joined, cleanupCause) {', 'if false {', 'origin identity'), 'lost errors.Is origin proof');
  reject(replaceOnce(goSource, 'if strings.Join(reversedMarkers, "\\x00") != strings.Join(reversedWant, "\\x00") ||\n\t\t!errors.Is(reversed, primaryCause) || !errors.Is(reversed, cleanupCause) ||', 'if false {', 'reversed expected pair and both causes'), 'removed reversed pair/cause assertion');
  reject(replaceOnce(goSource, 'reversedWant := []string{\n\t\t"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable",', 'reversedWant := []string{\n\t\t"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:deadline:watchdog_absolute_cap",', 'reversed primary marker'), 'changed reversed fail-closed marker');
  reject(replaceOnce(goSource, '!errors.Is(reversed, primaryCause) || !errors.Is(reversed, cleanupCause)', '!errors.Is(reversed, primaryCause)', 'reversed cleanup cause'), 'dropped reversed cleanup cause proof');
  reject(replaceOnce(goSource, '"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":matrix_case:deadline:" + string(planBrokerCPUControlWatchdogCap),', '"__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":cleanup:deadline:" + string(planBrokerCPUControlWatchdogCap),', 'canonical primary marker'), 'changed positive canonical marker');
  reject(replaceOnce(goSource, 'if repeated := planBrokerCPUFailureMarkers(budget, owner, joined); len(repeated) != 0 {', 'if repeated := planBrokerCPUFailureMarkers(budget, owner, joined); false {', 'budget repeat'), 'removed repeated-budget rejection');
  reject(replaceOnce(goSource, 'firstCleanup.caseName != ""', 'firstCleanup.caseName != string(planBrokerCPUControlWatchdogCap)', 'cleanup case isolation'), 'cleanup inherited matrix case');
  reject(replaceOnce(goSource, 'if firstMatrixCleanup != cleanupFromMatrix || firstMatrixCleanup.stage != planBrokerCPUStageCleanup || firstMatrixCleanup.reason != planBrokerCPUReasonDeadline || firstMatrixCleanup.caseName != "" {', 'if false {', 'direct matrix cleanup'), 'direct matrix cleanup isolation proof removed');
  reject(replaceOnce(goSource, 'firstMatrixCleanup.caseName != ""', 'firstMatrixCleanup.caseName == ""', 'direct matrix case isolation'), 'direct matrix cleanup case check inverted');
  reject(replaceOnce(goSource, 'if marker := planBrokerCPUFailureMarker(owner, cleanupFromMatrix); marker != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {', 'if marker := planBrokerCPUFailureMarker(owner, cleanupFromMatrix); marker != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline:watchdog_absolute_cap" {', 'matrix cleanup marker'), 'matrix case leaked into cleanup marker');
  reject(replaceOnce(goSource, 'if firstNestedPrimary := planBrokerCPUFirstFailure(nestedCleanup, false); firstNestedPrimary != primary {', 'if false {', 'nested first origin'), 'nested matrix first-origin proof removed');
  reject(replaceOnce(goSource, 'if firstNestedCleanup := planBrokerCPUFirstFailure(nestedCleanup, true); firstNestedCleanup != nestedCleanup || firstNestedCleanup.reason != planBrokerCPUReasonDeadline || firstNestedCleanup.caseName != "" || planBrokerCPUFailureMarker(owner, nestedCleanup) != "__PLAN_RELAUNCH_FAILURE_STAGE__:"+owner+":cleanup:deadline" {', 'if false {', 'nested cleanup isolation'), 'nested cleanup marker proof removed');
  reject(replaceOnce(goSource, 'if marker := planBrokerCPUFailureMarker(owner, invalidCase); marker != invalidWant || strings.Contains(marker, "foreign_case") {', 'if marker := planBrokerCPUFailureMarker(owner, invalidCase); false {', 'foreign matrix case'), 'foreign matrix case accepted');
  reject(replaceOnce(goSource, 'if marker := planBrokerCPUFailureMarker("unexpected-owner", primary); marker != foreignWant {', 'if marker := planBrokerCPUFailureMarker("unexpected-owner", primary); false {', 'foreign owner'), 'foreign owner accepted');
  const wrongInvalidOwnerExpectation = replaceOnce(goSource,
    'invalidOwnerWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + invalidOwner + ":unavailable:unavailable"',
    'invalidOwnerWant := "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable"',
    'crash invalid-owner expected marker');
  let invalidOwnerPredicateFailure = '';
  try { validateFailureMarkerControlSource(wrongInvalidOwnerExpectation); } catch (error) { invalidOwnerPredicateFailure = String(error?.message ?? error); }
  if (!invalidOwnerPredicateFailure.includes('pure Go marker control source predicate: invalid-owner expected marker must use the selected owner')) {
    throw new Error('invalid-owner source mutant was not rejected by the intended expected-owner binding predicate');
  }
  return true;
}

function selfTestPreReadyFailureFrameSource(goSource) {
  validatePreReadyFailureFrameSource('', goSource);
  const parentStart = goSource.indexOf('\nfunc runPlanBrokerCPUHolderControlParent(t *testing.T) {');
  const parentEnd = goSource.indexOf('\nfunc planBrokerCPUHolderControlBudget(', parentStart);
  const parent = goSource.slice(parentStart, parentEnd + 1);
  const branches = [
    ['CaseOrRoot', 'fixed holder control parent identity is invalid'],
    ['CaseOrRoot', 'fixed holder control root is not exact'],
    ['Budget', 'fixed holder control case has no finite deadline'],
    ['Unit', 'fixed holder control requires the original loaded active worker'],
    ['Plan', 'fixed holder control active plan is unavailable'],
    ['Launch', 'fixed holder control worker identity could not be captured'],
    ['WorkerPIDFD', 'fixed holder control worker pidfd could not be captured'],
    ['HolderHandshake', 'fixed holder control handshake failed'],
    ['CapHealthIdentity', 'fixed cap progress lost its bounded holder/phase identity'],
    ['CapHealthSend', 'fixed cap valid progress request failed'],
    ['CapHealthReply', 'fixed cap valid same-connection progress did not complete'],
    ['PhaseFrame', 'fixed control case/phase marker did not match its closed enum'],
    ['Transcript', 'fixed control transcript exceeds its independently derived frame/message budget'],
    ['HelperEarlyExit', 'controlled helper exited before its parent-death event'],
  ];
  const escape = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const [site, fatalText] of branches) {
    if (site === 'HolderHandshake') {
      const exact = 'site := planBrokerCPUHolderBranchFailureSite(err, control)\n\t\tif diagnostic, ok := planBrokerCPUHolderReadDiagnosticOf(err); ok && control == planBrokerCPUControlWatchdogNative && site == planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead) {\n\t\t\temitNativeHelperReadFailure(site, diagnostic)\n\t\t} else {\n\t\t\temitPreReadyFailure(site)\n\t\t}\n\t\tt.Fatal("fixed holder control handshake failed")';
      if (goSource.split(exact).length !== 2) throw new Error('positive pre-READY source binding is absent for HolderHandshake');
      const removed = goSource.replace(exact, 't.Fatal("fixed holder control handshake failed")');
      let omittedReason = '';
      try { validatePreReadyFailureFrameSource('', removed); } catch (error) { omittedReason = String(error?.message ?? error); }
      if (!omittedReason.includes('missing, duplicated, or relocated elected emission before its unchanged fatal')) throw new Error(`pre-READY omission mutant missed its exact branch predicate: HolderHandshake/${omittedReason}`);
      const relocated = goSource.replace(exact, 't.Fatal("fixed holder control handshake failed")\n\t\t' + exact.slice(0, exact.lastIndexOf('\n\t\tt.Fatal')));
      let relocatedReason = '';
      try { validatePreReadyFailureFrameSource('', relocated); } catch (error) { relocatedReason = String(error?.message ?? error); }
      if (!relocatedReason.includes('missing, duplicated, or relocated elected emission before its unchanged fatal')) throw new Error(`pre-READY relocation mutant missed its exact branch predicate: HolderHandshake/${relocatedReason}`);
      continue;
    }
    const call = site === 'HolderHandshake' ? 'emitPreReadyFailure(planBrokerCPUHolderBranchFailureSite(err, control))' : `emitPreReadyFailure(planBrokerCPUFailureSite${site})`;
    const pair = new RegExp(`${escape(call)}\\s*;?\\s*t\\.Fatal\\("${escape(fatalText)}"\\)`);
    const match = parent.match(pair);
    if (!match) throw new Error(`positive pre-READY source binding is absent for ${site}`);
    const removed = goSource.replace(match[0], match[0].replace(call, ''));
    let omittedReason = '';
    try { validatePreReadyFailureFrameSource('', removed); } catch (error) { omittedReason = String(error?.message ?? error); }
    if (!omittedReason.includes('missing, duplicated, or relocated elected emission before its unchanged fatal')) throw new Error(`pre-READY omission mutant missed its exact branch predicate: ${site}/${omittedReason}`);
    const relocated = goSource.replace(match[0], `t.Fatal("${fatalText}")\n\t\t${call}`);
    let relocatedReason = '';
    try { validatePreReadyFailureFrameSource('', relocated); } catch (error) { relocatedReason = String(error?.message ?? error); }
    if (!relocatedReason.includes('missing, duplicated, or relocated elected emission before its unchanged fatal')) throw new Error(`pre-READY relocation mutant missed its exact branch predicate: ${site}/${relocatedReason}`);
  }
  const rejectAt = (source, needle, replacement, intended, label) => {
    if (source.split(needle).length !== 2) throw new Error(`pre-READY mutation anchor is not exact once: ${label}`);
    let reason = '';
    try { validatePreReadyFailureFrameSource('', source.replace(needle, replacement)); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(intended)) throw new Error(`pre-READY source validator missed intended ${label} predicate: ${reason || 'accepted'}`);
  };
  rejectAt(goSource, '"CONTROL_FAILURE\\t" + string(control) + "\\t" + string(site) + "\\n"', 'fmt.Sprintf("CONTROL_FAILURE\\t%s\\t%s\\n", control, site)', 'private frame encoder/parser/writer lost a closed property', 'dynamic frame text');
  rejectAt(goSource, 'len(fields) != 3 || fields[0] != "CONTROL_FAILURE" || fields[1] != string(control) { return "", false }', 'len(fields) != 3 || fields[0] != "CONTROL_FAILURE" || fields[1] == "" { return "", false }', 'private frame encoder/parser/writer lost a closed property', 'selected case comparison');
  rejectAt(goSource, 'if control != planBrokerCPUControlWatchdogCap { return "", false }', 'if false { return "", false }', 'private frame encoder/parser/writer lost a closed property', 'cap-only site widening');
  rejectAt(goSource, 'planBrokerCPUParsePreReadyFailureFrame(first, control)', 'planBrokerCPUParsePreReadyFailureFrame("CONTROL_READY", control)', 'only the existing first bounded read may parse an exact selected failure frame before READY', 'failure frame as READY');
  rejectAt(goSource, 'case planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap:\n\t\treturn 3', 'case planBrokerCPUControlWatchdogNative, planBrokerCPUControlWatchdogCap:\n\t\treturn 4', 'failure-only observation must not change the original three-record positive inventory', 'positive count widening');
}

function selfTestTypedFailureStageSource(verifierSource, goSource) {
  validateTypedFailureStageSource(verifierSource, goSource);
  selfTestNativeHelperReadDiagnosticSource(verifierSource, goSource);
  const branchReject = (mutant, label, intended) => {
    let reason = '';
    try { validateHolderBranchAnnotationSource(mutant); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`holder-branch source predicate: ${intended}`)) throw new Error(`holder branch source controls missed ${label} mutant's intended predicate: ${reason || 'accepted'}`);
  };
  const branchReplace = (source, before, after, label) => {
    if (source.split(before).length !== 2) throw new Error(`holder branch source mutation anchor is not unique: ${label}`);
    return source.replace(before, after);
  };
  branchReject(branchReplace(goSource,
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootMetadata, errors.New("unit holder root ownership or non-root node group is not independently pinned"))',
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderLaunchCurrent, errors.New("unit holder root ownership or non-root node group is not independently pinned"))', 'swapped Mode site'), 'swapped actual branch', 'actual Mode return boundary is unannotated or misclassified');
  branchReject(branchReplace(goSource,
    'planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderCapRefRead, refErr)',
    'errors.New(refErr.Error())', 'lost cap read cause'), 'lost actual read cause', 'actual control return boundary is unannotated or misclassified');
  branchReject(branchReplace(goSource,
    'return errors.Join(primaryFailure, cleanupFailure)',
    'return errors.Join(cleanupFailure, primaryFailure)', 'cleanup reordered before primary'), 'actual primary-cleanup join reordering', 'actual planBrokerCPUJoinPrimaryAbort must preserve primary-before-cleanup order');
  branchReject(branchReplace(goSource,
    'if class == planBrokerCPUReasonChildHolderPipeSetup { cleanupClass = planBrokerCPUReasonChildHolderTokenSetup }',
    'if false { cleanupClass = planBrokerCPUReasonChildHolderTokenSetup }', 'cleanup class collision'), 'primary and cleanup annotation classes collided', 'primary and cleanup holder annotations must use distinct valid classes');
  branchReject(branchReplace(goSource,
    'if !planBrokerCPUHolderBranchReasonAllowed(class) || (planBrokerCPUHolderBranchCapOnly(class) && control != planBrokerCPUControlWatchdogCap) { return planBrokerCPUFailureSiteHolderHandshake }',
    'if !planBrokerCPUHolderBranchReasonAllowed(class) || false { return planBrokerCPUFailureSiteHolderHandshake }', 'selector cap widening'), 'actual selector cap widening', 'actual selector must reject cap-only holder classes on native watchdog cases');
  branchReject(branchReplace(goSource,
    'if planBrokerCPUHolderBranchCapOnly(planBrokerCPUFailureReason(site)) && control != planBrokerCPUControlWatchdogCap { return "", false }',
    'if false { return "", false }', 'encoder cap widening'), 'actual encoder cap widening', 'actual pre-READY encoder must reject cap-only holder classes on native watchdog cases');
  branchReject(branchReplace(goSource,
    'if _, ok := planBrokerCPUPreReadyFailureFrame(control, site); !ok { return "", false }',
    'if false { return "", false }', 'parser bypass'), 'actual parser encoder bypass', 'actual parser must consume the selected encoder guard for the parsed site');
  branchReject(branchReplace(goSource,
    'if (planBrokerCPUPreReadyFailureReasonCapOnly(failure.reason) || planBrokerCPUHolderBranchCapOnly(failure.reason)) && caseName != string(planBrokerCPUControlWatchdogCap) {',
    'if false {', 'formatter cap widening'), 'actual formatter cap widening', 'closed branch reasons must bind the exact watchdog owner/case and reject cap-only native parsing');
  branchReject(branchReplace(goSource,
    'originBranch(planBrokerCPUReasonIdentity, planBrokerCPUReasonChildHolderRootHandle, err)',
    'origin(planBrokerCPUReasonIdentity, err)', 'omitted root handle annotation'), 'omitted actual return annotation', 'actual Mode return boundary is unannotated or misclassified');
  selfTestPreReadyFailureFrameSource(goSource);
  const [life, crash] = inactiveWaitOwners;
  const lifeStages = ['matrix_admission', 'matrix_case', 'matrix_reserve'];
  const crashStages = ['parentdeath_setup', 'parentdeath_ready', 'parentdeath_signal', 'parentdeath_terminal', 'holder_acquire'];
  const reasons = ['deadline', 'identity', 'pipe_or_frame', 'unexpected_exit', 'unit_or_worker_state', 'descriptor_close', 'result_uncertain', 'unavailable'];
  for (const stage of lifeStages) for (const reason of reasons) {
    const casePart = stage === 'matrix_case' ? ':watchdog_native_expiry' : '';
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:${stage}:${reason}${casePart}`;
    const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
    const result = classifyTypedFailureStage(sample, [life]);
    if (result !== `failure_stage=${life}:${stage}:${reason}${casePart}`) throw new Error(`typed diagnostic rejected valid lifecycle ${stage}/${reason}`);
  }
  for (const stage of crashStages) for (const reason of reasons) {
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:${stage}:${reason}`;
    const sample = `=== RUN   ${crash}\n${marker}\n--- FAIL: ${crash} (0.10s)\n`;
    if (classifyTypedFailureStage(sample, [crash]) !== `failure_stage=${crash}:${stage}:${reason}`) throw new Error(`typed diagnostic rejected valid crash ${stage}/${reason}`);
  }
  const reportReasons = ['report_ready', 'report_metrics', 'report_result', 'report_pass', 'report_eof'];
  for (const matrixCase of ['watchdog_native_expiry', 'watchdog_absolute_cap']) {
    for (const reason of reportReasons) {
      const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:${reason}:${matrixCase}`;
      const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
      if (classifyTypedFailureStage(sample, [life]) !== `failure_stage=${life}:matrix_case:${reason}:${matrixCase}`) throw new Error(`typed diagnostic rejected positive watchdog report origin ${reason}/${matrixCase}`);
    }
  }
  const childCommonReasons = ['child_case_or_root', 'child_budget', 'child_unit', 'child_plan', 'child_launch', 'child_worker_pidfd', 'child_holder_handshake', 'child_phase_frame', 'child_transcript', 'child_helper_early_exit', 'child_holder_pre_spawn_binding', 'child_holder_pre_spawn_deadline', 'child_holder_root_metadata', 'child_holder_launch_current', 'child_holder_unit_current', 'child_holder_pipe_setup', 'child_holder_token_setup', 'child_holder_parent_pidfd', 'child_holder_root_handle', 'child_holder_spawn', 'child_holder_child_identity', 'child_holder_child_cgroup', 'child_holder_helper_read', 'child_holder_helper_shape'];
  const childCapReasons = ['child_cap_health_identity', 'child_cap_health_send', 'child_cap_health_reply', 'child_holder_cap_guard_send', 'child_holder_cap_guard_read', 'child_holder_cap_guard_shape', 'child_holder_cap_root_metadata', 'child_holder_cap_acquire_send', 'child_holder_cap_ref_read', 'child_holder_cap_ref_shape'];
  const childFailureCases = [
    ['watchdog_native_expiry', childCommonReasons],
    ['watchdog_absolute_cap', [...childCommonReasons, ...childCapReasons]],
  ];
  for (const [matrixCase, reasonsForCase] of childFailureCases) for (const reason of reasonsForCase) {
    const readDiagnostic = reason === 'child_holder_helper_read' && matrixCase === 'watchdog_native_expiry' ? ':diag:deadline:post_settled:signal_9' : '';
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:${reason}:${matrixCase}${readDiagnostic}`;
    const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
    const expectedDiagnostic = readDiagnostic ? ':read=deadline:wait=post_settled:signal_9' : '';
    if (classifyTypedFailureStage(sample, [life]) !== `failure_stage=${life}:matrix_case:${reason}:${matrixCase}${expectedDiagnostic}`) throw new Error(`typed diagnostic rejected valid first-read child branch marker ${reason}/${matrixCase}`);
  }
  for (const marker of [
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_cap_health_send:watchdog_native_expiry`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_cap_ref_shape:watchdog_native_expiry`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_unknown:watchdog_native_expiry`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_budget:startup_parentdeath`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:matrix_case:child_budget:watchdog_absolute_cap`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:cleanup:child_budget`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_budget:watchdog_absolute_cap:extra`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:deadline:unavailable:signal_9`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:deadline:post_settled:unavailable`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_absolute_cap:diag:deadline:post_settled:signal_9`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_cap_guard_read:watchdog_native_expiry:diag:deadline:post_settled:signal_9`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:deadline:post_settled:signal_65`,
    `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:deadline:post_settled:signal_09`,
  ]) {
    const owner = marker.includes(`:${crash}:`) ? crash : life;
    const sample = `=== RUN   ${owner}\n${marker}\n--- FAIL: ${owner} (0.10s)\n`;
    if (classifyTypedFailureStage(sample, [owner]) !== 'failure_stage=unavailable') throw new Error('typed classifier accepted a child failure marker outside the selected watchdog matrix case');
  }
  for (const reason of childCapReasons) {
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:${reason}:watchdog_native_expiry`;
    const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
    if (classifyTypedFailureStage(sample, [life]) !== 'failure_stage=unavailable') throw new Error(`typed classifier accepted cap-only reason on native watchdog: ${reason}`);
  }
  const privateFrameText = `=== RUN   ${life}\nCONTROL_FAILURE\twatchdog_absolute_cap\tchild_budget\n--- FAIL: ${life} (0.10s)\n`;
  if (classifyTypedFailureStage(privateFrameText, [life]) !== 'failure_stage=unavailable') throw new Error('outer typed marker classifier treated private CONTROL_FAILURE wire or raw framework text as a typed marker');
  const rejectSourceMutant = (source, before, after, label, expectedMessage = 'watchdog report origins must remain exact') => {
    if (source.split(before).length !== 2) throw new Error(`watchdog origin mutation anchor is not exact once: ${label}`);
    let rejected = false;
    try { validateTypedFailureStageSource(verifierSource, source.replace(before, after)); } catch (error) { rejected = String(error?.message ?? error).includes(expectedMessage); }
    if (!rejected) throw new Error(`typed source validator accepted ${label} mutant`);
  };
  const rejectSourceRegionMutant = (source, start, end, before, after, label) => {
    const left = source.indexOf(start), right = source.indexOf(end, left + start.length);
    if (left < 0 || right <= left) throw new Error(`watchdog origin region missing: ${label}`);
    const region = source.slice(left, right);
    if (region.split(before).length !== 2) throw new Error(`watchdog origin region anchor is not exact once: ${label}`);
    const mutant = source.slice(0, left) + region.replace(before, after) + source.slice(right);
    let rejected = false;
    try { validateTypedFailureStageSource(verifierSource, mutant); } catch (error) { rejected = String(error?.message ?? error).includes('watchdog report origins must remain exact'); }
    if (!rejected) throw new Error(`typed source validator accepted ${label} mutant`);
  };
  rejectSourceMutant(goSource,
    'failure(planBrokerCPUReasonReportResult, resultFailure)',
    'failure(planBrokerCPUReasonReportPass, resultFailure)', 'swapped RESULT origin');
  rejectSourceMutant(goSource,
    'failure(planBrokerCPUReasonReportPass, passFailure)',
    'failure(planBrokerCPUReasonReportResult, passFailure)', 'swapped PASS origin');
  rejectSourceRegionMutant(goSource, 'first, err := stdoutReader.read(deadline)', '\n\tif control == planBrokerCPUControlNegativeRefError {', 'if watchdogReport { reason = planBrokerCPUReasonReportReady }', 'if watchdogReport { reason = planBrokerCPUReasonReportMetrics }', 'wrong READY origin');
  rejectSourceRegionMutant(goSource, 'if bytesErr != nil || messagesErr != nil || frameErr != nil || transcriptBytes < 1', '\n\thelperIdentity, helperIdentityErr := capturePlanBrokerCPUProcessIdentity(helperPID)', 'if watchdogReport { reason = planBrokerCPUReasonReportMetrics }', 'if watchdogReport { reason = planBrokerCPUReasonReportReady }', 'wrong metrics origin');
  rejectSourceMutant(goSource,
    'second != "CONTROL_RESULT\\t"+string(control)+"\\twatchdog_sigalrm"',
    'second != "CONTROL_RESULT\\t"+string(control)', 'weakened RESULT comparison');
  rejectSourceMutant(goSource,
    'requireReportEOF(deadline, planBrokerCPUReasonReportEOF)',
    'requireReportEOF(deadline, planBrokerCPUReasonPipe)', 'dropped EOF origin');
  rejectSourceMutant(goSource,
    'if err := requireReportEOF(deadline, planBrokerCPUReasonReportEOF); err != nil { return failure(planBrokerCPUReasonPipe, err) }',
    '', 'omitted watchdog EOF call');
  const widenedClassifier = verifierSource.replace("if (watchdogReportReasons.has(reason) && (stage !== 'matrix_case' || owner !== inactiveWaitOwners[0] || !['watchdog_native_expiry', 'watchdog_absolute_cap'].includes(matrixCase))) return unavailable;", 'if (false) return unavailable;');
  let widenedRejected = false;
  try { validateTypedFailureStageSource(widenedClassifier, goSource); } catch (error) { widenedRejected = String(error?.message ?? error).includes('typed failure-stage reducer is missing if (watchdogReportReasons.has(reason)'); }
  if (!widenedRejected) throw new Error('typed source validator accepted widened watchdog reason classification');
  const widenedCapOnlyClassifier = verifierSource.replace("if (childCapOnlyFailureReasons.has(reason) && matrixCase !== 'watchdog_absolute_cap') return unavailable;", 'if (false) return unavailable;');
  let widenedCapOnlyRejected = false;
  try { validateTypedFailureStageSource(widenedCapOnlyClassifier, goSource); } catch (error) { widenedCapOnlyRejected = String(error?.message ?? error).includes('typed failure-stage reducer is missing its cap-only case gate'); }
  if (!widenedCapOnlyRejected) throw new Error('typed source validator accepted cap-only child reasons on native watchdog cases');
  const widenedSummary = verifierSource.replace("return Buffer.byteLength(diagnostic, 'utf8') <= maxFailureStageDiagnosticBytes ? diagnostic : unavailable;", 'return diagnostic;');
  let widenedSummaryRejected = false;
  let widenedSummaryReason = '';
  try { validateTypedFailureStageSource(widenedSummary, goSource); } catch (error) { widenedSummaryReason = String(error?.message ?? error); widenedSummaryRejected = widenedSummaryReason.includes('typed failure-stage reducer is missing maxFailureStageDiagnosticBytes'); }
  if (!widenedSummaryRejected) throw new Error(`typed source validator did not reject summary-cap mutant for the intended predicate: ${widenedSummaryReason || 'accepted'}`);
  const cleanup = `=== RUN   ${crash}\n__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:parentdeath_terminal:unexpected_exit\n__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:cleanup:descriptor_close\n--- FAIL: ${crash} (0.10s)\n`;
  if (classifyTypedFailureStage(cleanup, [crash]) !== `failure_stage=${crash}:parentdeath_terminal:unexpected_exit,cleanup:descriptor_close`) throw new Error('typed diagnostic did not preserve a primary plus separately classified cleanup failure');
  const cleanupUnknown = cleanup.replace(':cleanup:descriptor_close', ':cleanup:unavailable');
  if (classifyTypedFailureStage(cleanupUnknown, [crash]) !== `failure_stage=${crash}:parentdeath_terminal:unexpected_exit,cleanup:unavailable`) throw new Error('typed diagnostic did not preserve an explicitly unavailable cleanup origin after a primary');
  const cleanupOnly = `=== RUN   ${crash}\n__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:unavailable:unavailable\n__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:cleanup:descriptor_close\n--- FAIL: ${crash} (0.10s)\n`;
  if (classifyTypedFailureStage(cleanupOnly, [crash]) !== `failure_stage=${crash}:unavailable:unavailable,cleanup:descriptor_close`) throw new Error('standalone cleanup must not be promoted to a primary diagnostic');
  const capCleanup = `=== RUN   ${life}\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:pipe_or_frame:watchdog_absolute_cap\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:cleanup:descriptor_close\n--- FAIL: ${life} (0.10s)\n`;
  if (classifyTypedFailureStage(capCleanup, [life]) !== `failure_stage=${life}:matrix_case:pipe_or_frame:watchdog_absolute_cap,cleanup:descriptor_close`) throw new Error('absolute-cap primary plus independent cleanup failure must retain its valid ordered two-marker diagnostic');
  const phantomCapCleanup = capCleanup.replace(`:${life}:cleanup:descriptor_close`, `:${life}:cleanup:descriptor_close:watchdog_absolute_cap`);
  if (classifyTypedFailureStage(phantomCapCleanup, [life]) !== 'failure_stage=unavailable') throw new Error('cleanup marker must not inherit a matrix case name');
  const resultCleanup = `=== RUN   ${life}\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:report_result:watchdog_absolute_cap\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:cleanup:unexpected_exit\n--- FAIL: ${life} (0.10s)\n`;
  if (classifyTypedFailureStage(resultCleanup, [life]) !== `failure_stage=${life}:matrix_case:report_result:watchdog_absolute_cap,cleanup:unexpected_exit`) throw new Error('watchdog RESULT failure plus independent cleanup exit must preserve its distinct ordered origins');
  for (const reason of reportReasons) {
    const base = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:${reason}:watchdog_absolute_cap`;
    for (const marker of [
      base.replace(':matrix_case:', ':cleanup:'),
      base.replace(':matrix_case:', ':matrix_reserve:'),
      `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:cleanup:${reason}`,
      `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_reserve:${reason}`,
      `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:${reason}`,
      base.replace('watchdog_absolute_cap', 'startup_parentdeath'),
      base.replace(`:${life}:`, `:${crash}:`),
      base.replace('watchdog_absolute_cap', 'unknown_case'),
    ]) {
      const owner = marker.includes(`:${crash}:`) ? crash : life;
      const sample = `=== RUN   ${owner}\n${marker}\n--- FAIL: ${owner} (0.10s)\n`;
      if (classifyTypedFailureStage(sample, [owner]) !== 'failure_stage=unavailable') throw new Error(`typed diagnostic accepted forbidden watchdog report context ${reason}`);
    }
  }
  const overBudget = cleanup.replace('--- FAIL:', '__PLAN_RELAUNCH_FAILURE_STAGE__:' + crash + ':cleanup:descriptor_close\n--- FAIL:');
  if (classifyTypedFailureStage(overBudget, [crash]) !== 'failure_stage=unavailable') throw new Error('owner diagnostic reducer accepted more than one primary plus one cleanup emission');
  const good = `=== RUN   ${life}\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry\n--- FAIL: ${life} (0.10s)\n`;
  const invalid = [
    good.replace('__PLAN_RELAUNCH_FAILURE_STAGE__:', ''),
    good.replace(`:${life}:matrix_case`, ':TestWrongOwner:matrix_case'),
    good.replace(`__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry`, `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:cleanup:descriptor_close\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry`),
    good.replace('matrix_case:result_uncertain:watchdog_native_expiry', 'matrix_case:result_uncertain:private_path'),
    good.replace('result_uncertain', 'pid=1234'),
    good.replace('matrix_case', 'unknown_stage'),
    good.replace(`--- FAIL: ${life}`, `--- PASS: ${life}`),
    good.replace(`=== RUN   ${life}\n`, ''),
    good.replace(`=== RUN   ${life}\n`, `=== RUN   ${life}\n=== RUN   ${life}\n`),
    good.replace(`__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry\n`, ''),
    good.replace(`__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry`, `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry\n__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:result_uncertain:watchdog_native_expiry`),
    good.replace(`=== RUN   ${life}\n`, `=== RUN   ${life}\n` + '__PLAN_RELAUNCH_FAILURE_STAGE__:foreign:cleanup:descriptor_close\n'),
    `${good}__PLAN_RELAUNCH_FAILURE_STAGE__:${crash}:cleanup:descriptor_close\n`,
    good.replace(` (0.10s)`, ''),
    `${good}${'x'.repeat(maxFailureLineBytes + 1)}`,
  ];
  for (const [index, output] of invalid.entries()) if (classifyTypedFailureStage(output, [life]) !== 'failure_stage=unavailable') throw new Error(`typed stage reducer accepted invalid control ${index}`);
  if (classifyTypedFailureStage(good + 'x'.repeat(maxFailureCaptureBytes + 1), [life]) !== 'failure_stage=unavailable') throw new Error('typed stage reducer accepted an over-limit full capture');
  const bypass = verifierSource.replace('      const siteDiagnostic = classifyOptInTestFailureSites(output, expected);\n      const stageDiagnostic = classifyTypedFailureStage(output, expected);', "      const siteDiagnostic = classifyOptInTestFailureSites(output, expected);\n      const stageDiagnostic = 'failure_stage=unavailable';");
  let bypassRejected = false;
  try { validateTypedFailureStageSource(bypass, goSource); } catch { bypassRejected = true; }
  const hostileOwner = goSource.replace('if !validOwner { return "__PLAN_RELAUNCH_FAILURE_STAGE__:unavailable:unavailable:unavailable" }', 'if !validOwner { return "__PLAN_RELAUNCH_FAILURE_STAGE__:" + owner + ":unavailable:unavailable" }');
  let hostileOwnerRejected = false;
  try { validateTypedFailureStageSource(verifierSource, hostileOwner); } catch { hostileOwnerRejected = true; }
  const exactRegionMutation = (source, start, end, before, after) => {
    const left = source.indexOf(start), right = source.indexOf(end, left + start.length);
    if (left < 0 || right <= left) throw new Error(`source-control region missing: ${start}`);
    const region = source.slice(left, right);
    if (region.split(before).length !== 2) throw new Error(`source-control target is not unique in region: ${before}`);
    return source.slice(0, left) + region.replace(before, after) + source.slice(right);
  };
  const leakedCleanupCase = exactRegionMutation(goSource, 'func planBrokerCPUFailureAt(', '\nfunc planBrokerCPUCleanupFailure(', 'if stage == planBrokerCPUStageMatrixCase && caseName == "" { caseName = existing.caseName }', 'if caseName == "" { caseName = existing.caseName }');
  let leakedCleanupCaseRejected = false;
  try { validateTypedFailureStageSource(verifierSource, leakedCleanupCase); } catch { leakedCleanupCaseRejected = true; }
  if (!leakedCleanupCaseRejected) throw new Error('typed diagnostic controls accepted matrix-case inheritance by a cleanup wrapper');
  const modelFailurePair = (primaryReason, cleanupReason) => {
    const allowed = new Set(['deadline', 'identity', 'pipe_or_frame', 'unexpected_exit', 'unit_or_worker_state', 'descriptor_close', 'result_uncertain', 'unavailable']);
    const primary = allowed.has(primaryReason) ? primaryReason : 'unavailable';
    if (!cleanupReason) return [primary];
    return [primary, `cleanup:${allowed.has(cleanupReason) ? cleanupReason : 'unavailable'}`];
  };
  if (JSON.stringify(modelFailurePair('pipe_or_frame', 'descriptor_close')) !== JSON.stringify(['pipe_or_frame', 'cleanup:descriptor_close']) ||
      JSON.stringify(modelFailurePair('identity', 'unexpected_exit')) !== JSON.stringify(['identity', 'cleanup:unexpected_exit']) ||
      JSON.stringify(modelFailurePair('identity', null)) !== JSON.stringify(['identity']) ||
      JSON.stringify(modelFailurePair('unavailable', null)) !== JSON.stringify(['unavailable']) ||
      JSON.stringify(modelFailurePair(null, 'descriptor_close')) !== JSON.stringify(['unavailable', 'cleanup:descriptor_close'])) throw new Error('closed primary/cleanup source model collapsed primary and cleanup origins');
  const lostParentOrigin = exactRegionMutation(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'return failure(planBrokerCPUStageParentSetup, planBrokerCPUReasonPipe, errors.New("parent-death report pipe could not be created"))', 'return errors.New("parent-death report pipe could not be created")');
  let lostParentOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostParentOrigin); } catch { lostParentOriginRejected = true; }
  const lostReadyOrigin = exactRegionMutation(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonPipe, errors.New("parent helper did not emit one bounded identity frame; preserving fixture"))', 'return failure(planBrokerCPUStageParentReady, planBrokerCPUReasonUnavailable, errors.New("parent helper did not emit one bounded identity frame; preserving fixture"))');
  let lostReadyOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostReadyOrigin); } catch { lostReadyOriginRejected = true; }
  const lostSignalOrigin = exactRegionMutation(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonIdentity, errors.New("parent helper was not live immediately before induced death; preserving fixture"))', 'return failure(planBrokerCPUStageParentSignal, planBrokerCPUReasonUnavailable, errors.New("parent helper was not live immediately before induced death; preserving fixture"))');
  let lostSignalOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostSignalOrigin); } catch { lostSignalOriginRejected = true; }
  const lostTerminalOrigin = exactRegionMutation(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonDeadline, errors.New("exact parent helper did not exit within its fixed bound; preserving fixture"))', 'return failure(planBrokerCPUStageParentTerminal, planBrokerCPUReasonUnavailable, errors.New("exact parent helper did not exit within its fixed bound; preserving fixture"))');
  let lostTerminalOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostTerminalOrigin); } catch { lostTerminalOriginRejected = true; }
  const acquisitionStart = 'func planBrokerCPUJoinPrimaryAbort(';
  const abortCleanupStart = '\nfunc planBrokerCPUAbortCleanup(';
  const invertedAcquisition = exactRegionMutation(goSource, acquisitionStart, abortCleanupStart, 'primaryFailure := planBrokerCPUFailureOrigin(reason, primary)\n\tif holder == nil { return primaryFailure }\n\tabortErr := holder.abort()', 'abortErr := holder.abort()\n\tprimaryFailure := planBrokerCPUFailureOrigin(reason, errors.Join(primary, abortErr))');
  let invertedAcquisitionRejected = false;
  try { validateTypedFailureStageSource(verifierSource, invertedAcquisition); } catch { invertedAcquisitionRejected = true; }
  const untypedAbortJoin = exactRegionMutation(goSource, acquisitionStart, abortCleanupStart, 'cleanupFailure := planBrokerCPUCleanupFailure(planBrokerCPUFailureReasonOf(abortErr), abortErr)', 'cleanupFailure := abortErr');
  let untypedAbortJoinRejected = false;
  try { validateTypedFailureStageSource(verifierSource, untypedAbortJoin); } catch { untypedAbortJoinRejected = true; }
  const releaseStart = 'func (holder *planBrokerCPUUnitHolder) release() error {';
  const eofStart = '\nfunc (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(';
  const abortStart = '\nfunc (holder *planBrokerCPUUnitHolder) abort() error {';
  const closeFilesStart = '\nfunc (holder *planBrokerCPUUnitHolder) closeFiles() error {';
  const identityStart = '\nfunc planBrokerCPUHolderIdentityCurrent(';
  const readFrameStart = 'func (holder *planBrokerCPUUnitHolder) readFrameUntil(';
  const healthStart = '\nfunc (holder *planBrokerCPUUnitHolder) health(';
  const releaseUnitBlanket = exactRegionMutation(goSource, releaseStart, eofStart, 'finish := func(err error) error { holder.releaseErr = err; return holder.releaseErr }', 'finish := func(err error) error { holder.releaseErr = planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, err); return holder.releaseErr }');
  let releaseUnitRejected = false;
  try { validateTypedFailureStageSource(verifierSource, releaseUnitBlanket); } catch { releaseUnitRejected = true; }
  const releaseDeadlineLost = exactRegionMutation(goSource, releaseStart, eofStart, 'return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder did not reap within the fixed release deadline")))', 'return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder did not reap within the fixed release deadline")))');
  let releaseDeadlineRejected = false;
  try { validateTypedFailureStageSource(verifierSource, releaseDeadlineLost); } catch { releaseDeadlineRejected = true; }
  const releaseExitLost = exactRegionMutation(goSource, releaseStart, eofStart, 'return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, errors.New("unit holder normal release did not produce one zero-exit Wait")))', 'return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder normal release did not produce one zero-exit Wait")))');
  let releaseExitRejected = false;
  try { validateTypedFailureStageSource(verifierSource, releaseExitLost); } catch { releaseExitRejected = true; }
  const releaseEOFLost = exactRegionMutation(goSource, releaseStart, eofStart, 'if err := holder.requireStatusEOFUntil(deadline); err != nil { return finish(err) }', 'if err := holder.requireStatusEOFUntil(deadline); err != nil { return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, err)) }');
  let releaseEOFRejected = false;
  try { validateTypedFailureStageSource(verifierSource, releaseEOFLost); } catch { releaseEOFRejected = true; }
  const releaseCloseLost = exactRegionMutation(goSource, releaseStart, eofStart, 'return finish(holder.closeFiles())', 'return finish(planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, holder.closeFiles()))');
  let releaseCloseRejected = false;
  try { validateTypedFailureStageSource(verifierSource, releaseCloseLost); } catch { releaseCloseRejected = true; }
  const readDeadlineOriginLost = exactRegionMutation(goSource, readFrameStart, healthStart, 'if !deadline.After(time.Now()) { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder response budget or state is invalid")) }', 'if !deadline.After(time.Now()) { return "", planBrokerCPUFailureOrigin(planBrokerCPUReasonUnit, errors.New("unit holder response budget or state is invalid")) }');
  let readDeadlineOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, readDeadlineOriginLost); } catch { readDeadlineOriginRejected = true; }
  const eofDeadlineOriginLost = exactRegionMutation(goSource, eofStart, abortStart, 'return planBrokerCPUFailureOrigin(planBrokerCPUReasonDeadline, errors.New("unit holder status stream did not reach exact EOF within the shared release deadline"))', 'return errors.New("unit holder status stream did not reach exact EOF within the shared release deadline")');
  let eofDeadlineOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, eofDeadlineOriginLost); } catch { eofDeadlineOriginRejected = true; }
  const eofDescriptorOriginLost = exactRegionMutation(goSource, eofStart, abortStart, 'return planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, errors.New("unit holder status EOF descriptor reported an invalid event"))', 'return errors.New("unit holder status EOF descriptor reported an invalid event")');
  let eofDescriptorOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, eofDescriptorOriginLost); } catch { eofDescriptorOriginRejected = true; }
  const abortDescriptorCloseLost = exactRegionMutation(goSource, closeFilesStart, identityStart, 'if err := unix.Close(holder.childPIDFD); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, &planBrokerCPUFixedMessageFailure{message: "unit holder pidfd close failed", cause: err})) }', 'if err := unix.Close(holder.childPIDFD); err != nil { result = errors.Join(result, errors.New("unit holder pidfd close failed")) }');
  let abortDescriptorCloseRejected = false;
  try { validateTypedFailureStageSource(verifierSource, abortDescriptorCloseLost); } catch { abortDescriptorCloseRejected = true; }
  const abortPipeCloseLost = exactRegionMutation(goSource, abortStart, closeFilesStart, 'if err := holder.guard.Close(); err != nil { result = errors.Join(result, planBrokerCPUFailureOrigin(planBrokerCPUReasonClose, err)) }', 'if err := holder.guard.Close(); err != nil { result = errors.Join(result, err) }');
  let abortPipeCloseRejected = false;
  try { validateTypedFailureStageSource(verifierSource, abortPipeCloseLost); } catch { abortPipeCloseRejected = true; }
  const lostSurvivor = exactRegionMutation(goSource, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'result = &planBrokerCPUSurvivorPredicateFailure{err: result}', 'result = result');
  let lostSurvivorRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostSurvivor); } catch { lostSurvivorRejected = true; }
  const survivorLiteralDrift = exactRegionMutation(goSource, 'func (failure *planBrokerCPUSurvivorPredicateFailure) Error() string {', '\nfunc (failure *planBrokerCPUSurvivorPredicateFailure) Unwrap() error', 'direct child survived exact parent death and required pidfd-only cleanup', 'direct child survived exact parent death and required pidfd-only emergency cleanup');
  let survivorLiteralRejected = false;
  try { validateTypedFailureStageSource(verifierSource, survivorLiteralDrift); } catch { survivorLiteralRejected = true; }
  const lifecycleOwnerStart = 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {';
  const crashOwnerStart = 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {';
  const workerOwnerStart = '\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {';
  const freshBudget = exactRegionMutation(goSource, lifecycleOwnerStart, crashOwnerStart, 'planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPULifecycleSequence", planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUnavailable, "", cleanupErr))', 'planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, "TestCheckpointPlanRelaunchCPULifecycleSequence", planBrokerCPUFailureAt(planBrokerCPUStageCleanup, planBrokerCPUReasonUnavailable, "", cleanupErr))');
  let freshBudgetRejected = false;
  try { validateTypedFailureStageSource(verifierSource, freshBudget); } catch { freshBudgetRejected = true; }
  const lostCleanupOrigin = exactRegionMutation(goSource, lifecycleOwnerStart, crashOwnerStart, 'planBrokerCPUCleanupFailure(planBrokerCPUReasonIdentity, errors.New("transient unit does not join an exact held fixture launch; preserving private fixture"))', 'errors.New("transient unit does not join an exact held fixture launch; preserving private fixture")');
  let lostCleanupOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostCleanupOrigin); } catch { lostCleanupOriginRejected = true; }
  const lostCrashCleanupOrigin = exactRegionMutation(goSource, crashOwnerStart, workerOwnerStart, 'if err := stopPlanBrokerCPUUnrelatedChild(unrelated); err != nil {\n\t\t\t\tresult = errors.Join(result, planBrokerCPUCleanupFailure(planBrokerCPUReasonUnavailable, err))', 'if err := stopPlanBrokerCPUUnrelatedChild(unrelated); err != nil {\n\t\t\t\tresult = errors.Join(result, err)');
  let lostCrashCleanupOriginRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostCrashCleanupOrigin); } catch { lostCrashCleanupOriginRejected = true; }
  const lostCaseOrigins = exactRegionMutation(goSource, 'func runPlanBrokerCPUHolderControlCase(', '\nfunc runPlanBrokerCPUHolderControlMatrix(', 'return planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, reason, string(control), planBrokerCPUFailureOrigin(reason, err))', 'return planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, reason, string(control), err)');
  let lostCaseOriginsRejected = false;
  try { validateTypedFailureStageSource(verifierSource, lostCaseOrigins); } catch { lostCaseOriginsRejected = true; }
  if (!hostileOwnerRejected || !lostParentOriginRejected || !lostReadyOriginRejected || !lostSignalOriginRejected || !lostTerminalOriginRejected || !invertedAcquisitionRejected || !untypedAbortJoinRejected || !releaseUnitRejected || !releaseDeadlineRejected || !releaseExitRejected || !releaseEOFRejected || !releaseCloseRejected || !readDeadlineOriginRejected || !eofDeadlineOriginRejected || !eofDescriptorOriginRejected || !abortDescriptorCloseRejected || !abortPipeCloseRejected || !survivorLiteralRejected || !lostSurvivorRejected || !freshBudgetRejected || !lostCleanupOriginRejected || !lostCrashCleanupOriginRejected || !lostCaseOriginsRejected) throw new Error(`typed origin controls accepted an unsafe owner fallback or a lost branch, cleanup, acquisition, release, or survivor distinction: ${[hostileOwnerRejected, lostParentOriginRejected, lostReadyOriginRejected, lostSignalOriginRejected, lostTerminalOriginRejected, invertedAcquisitionRejected, untypedAbortJoinRejected, releaseUnitRejected, releaseDeadlineRejected, releaseExitRejected, releaseEOFRejected, releaseCloseRejected, readDeadlineOriginRejected, eofDeadlineOriginRejected, eofDescriptorOriginRejected, abortDescriptorCloseRejected, abortPipeCloseRejected, survivorLiteralRejected, lostSurvivorRejected, freshBudgetRejected, lostCleanupOriginRejected, lostCrashCleanupOriginRejected, lostCaseOriginsRejected].join(',')}`);
  if (!bypassRejected) throw new Error('typed diagnostic controls accepted a bypassed actual failure reducer');
  const removedGoEmitter = exactRegionMutation(goSource, lifecycleOwnerStart, crashOwnerStart, `planBrokerCPUFailureMarkers(&failureEmission, "${life}", err)`, `planBrokerCPUFailureMarkers(&planBrokerCPUFailureEmission{}, "${life}", err)`);
  let emitterRejected = false;
  try { validateTypedFailureStageSource(verifierSource, removedGoEmitter); } catch { emitterRejected = true; }
  if (!emitterRejected) throw new Error('typed diagnostic controls accepted a marker emission that bypassed the actual owner-wide budget');
  return true;
}

function selfTestNativeHelperReadDiagnosticSource(verifierSource, goSource) {
  const rejectGo = (before, after, intended, label) => {
    if (goSource.split(before).length !== 2) throw new Error(`native helper-read mutation anchor is not unique: ${label}`);
    let reason = '';
    try { validateTypedFailureStageSource(verifierSource, goSource.replace(before, after)); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`native helper-read diagnostic source predicate: ${intended}`)) throw new Error(`native helper-read source control missed ${label} intended predicate: ${reason || 'accepted'}`);
  };
  rejectGo(
    '"CONTROL_FAILURE\\t" + string(control) + "\\t" + string(site) + "\\t" + diagnostic.readReason + "\\t" + diagnostic.waitPhase + "\\t" + diagnostic.waitStatus + "\\n"',
    '"CONTROL_FAILURE\\t" + string(control) + "\\t" + string(site) + "\\t" + diagnostic.waitPhase + "\\t" + diagnostic.waitStatus + "\\n"',
    'failure frame must carry only the exact closed native read reason', 'omitted read reason');
  rejectGo(
    'if !settledAfterAbort { return diagnostic, true }',
    'if !settledAfterAbort { diagnostic.waitPhase = "post_settled"; diagnostic.waitStatus = "signal_9"; return diagnostic, true }',
    'state validator is missing if !settledAfterAbort { return diagnostic, true }', 'invented unsettled status');
  rejectGo(
    'else { diagnostic.waitPhase = "post_settled" }',
    'else { diagnostic.waitPhase = "pre_settled" }',
    'state validator is missing diagnostic.waitPhase = "post_settled"', 'post status mislabeled as pre');
  rejectGo(
    'control != planBrokerCPUControlWatchdogNative || site != planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead)',
    'control != planBrokerCPUControlWatchdogCap || site != planBrokerCPUPreReadyFailureSite(planBrokerCPUReasonChildHolderHelperRead)',
    'failure frame must carry only the exact closed native read reason', 'native/cap substitution');
  rejectGo(
    'if len(fields) != 6 || fields[0] != "CONTROL_FAILURE"',
    'if len(fields) != 7 || fields[0] != "CONTROL_FAILURE"',
    'native diagnostic parser/writer must be exact, closed, one-record and single checked write', 'duplicate/extra field acceptance');
  rejectGo(
    'if len(frame) > 192 { return "", false }\n\treturn frame, true\n}\n\nfunc planBrokerCPUParseNativeHelperReadFailureFrame(',
    'if len(frame) > 193 { return "", false }\n\treturn frame, true\n}\n\nfunc planBrokerCPUParseNativeHelperReadFailureFrame(',
    'failure frame must carry only the exact closed native read reason', 'widened diagnostic frame bound');
  rejectGo(
    'settledBeforeAbort := planBrokerCPUHolderReadDiagnosticBeforeAbort(holder)\n\tjoined := planBrokerCPUJoinPrimaryAbort(reason, primary, holder)',
    'joined := planBrokerCPUJoinPrimaryAbort(reason, primary, holder)\n\tsettledBeforeAbort := planBrokerCPUHolderReadDiagnosticBeforeAbort(holder)',
    'read reason and pre-abort wait snapshot must precede exactly one unchanged primary-first abort', 'reordered cleanup/capture');
  rejectGo(
    'return planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err)',
    'return planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonUncertain, string(testCase.control), fmt.Errorf("fixed holder control %s failed: %w", testCase.control, err))',
    'actual matrix wrapper must value-copy only a validated selected native primary diagnostic through the real selector and formatter', 'bypassed actual matrix propagation');
  rejectGo(
    'return planBrokerCPUHolderControlMatrixFailure(string(testCase.control), err)',
    'return planBrokerCPUHolderControlMatrixFailure(testCase.control, err)',
    'actual matrix wrapper must value-copy only a validated selected native primary diagnostic through the real selector and formatter', 'named control passed without string conversion');
  rejectGo(
    'diagnostic := *inner.helperReadDiagnostic\n\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)',
    'wrappedFailure.helperReadDiagnostic = inner.helperReadDiagnostic',
    'actual matrix wrapper must value-copy only a validated selected native primary diagnostic through the real selector and formatter', 'aliased diagnostic pointer');
  rejectGo(
    'diagnostic := *inner.helperReadDiagnostic\n\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)',
    '// omitted diagnostic attachment by source control',
    'actual matrix wrapper must value-copy only a validated selected native primary diagnostic through the real selector and formatter', 'omitted wrapper attachment');

  const life = 'TestCheckpointPlanRelaunchCPULifecycleSequence';
  const positives = [
    ['deadline', 'pre_settled', 'exit_17'],
    ['pipe_or_frame', 'post_settled', 'signal_9'],
    ['unexpected_exit', 'unavailable', 'unavailable'],
  ];
  for (const [reason, phase, status] of positives) {
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:diag:${reason}:${phase}:${status}`;
    const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
    const expected = `failure_stage=${life}:matrix_case:child_holder_helper_read:watchdog_native_expiry:read=${reason}:wait=${phase}:${status}`;
    if (classifyTypedFailureStage(sample, [life]) !== expected) throw new Error(`Node failure reducer rejected known-positive native diagnostic ${reason}/${phase}/${status}`);
  }
  for (const [reason, phase, status] of [
    ['deadline', 'unavailable', 'signal_9'],
    ['deadline', 'pre_settled', 'unavailable'],
    ['deadline', 'post_settled', 'exit_256'],
    ['deadline', 'post_settled', 'signal_65'],
    ['deadline', 'post_settled', 'signal_09'],
    ['deadline', 'post_settled', 'signal_9'],
  ]) {
    const matrixCase = reason === 'deadline' && phase === 'post_settled' && status === 'signal_9' ? 'watchdog_absolute_cap' : 'watchdog_native_expiry';
    const marker = `__PLAN_RELAUNCH_FAILURE_STAGE__:${life}:matrix_case:child_holder_helper_read:${matrixCase}:diag:${reason}:${phase}:${status}`;
    const sample = `=== RUN   ${life}\n${marker}\n--- FAIL: ${life} (0.10s)\n`;
    if (classifyTypedFailureStage(sample, [life]) !== 'failure_stage=unavailable') throw new Error(`Node failure reducer accepted invalid native diagnostic ${reason}/${phase}/${status}`);
  }
  const widenedOutput = verifierSource.replace('${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\\n', '${diagnostic}; ${siteDiagnostic}; ${stageDiagnostic}\\n');
  let outputReason = '';
  try { validateNativeHelperReadDiagnosticSource(widenedOutput, goSource); } catch (error) { outputReason = String(error?.message ?? error); }
  if (!outputReason.includes('bounded stage/read evidence must appear before potentially lengthy test-site diagnostics')) throw new Error(`native helper-read source control missed output-order mutation: ${outputReason || 'accepted'}`);
}

function selfTestPureDiagnosticControlSource(verifierSource, goSource) {
  validatePureDiagnosticControlSource(verifierSource, goSource);
  const expected = 'pure diagnostic controls must be a standalone exact test that calls the existing in-memory controls and reports their original error';
  const reject = (mutantVerifier, mutantGo, label) => {
    let reason = '';
    try { validatePureDiagnosticControlSource(mutantVerifier, mutantGo); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(expected)) throw new Error(`pure diagnostic source control missed ${label}: ${reason || 'accepted'}`);
  };
  const testStart = `func TestPlanBrokerCPUFailureMarkerControlsPure(t *testing.T) {`;
  const testEnd = '\nconst planBrokerCPUDescriptorGuardControlAssertion';
  const goRegion = uniqueSourceRegion(goSource, testStart, testEnd);
  const controlsStart = 'func verifyPlanBrokerCPUFailureMarkerControls() error {';
  const controlsEnd = '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence';
  const controlsRegion = uniqueSourceRegion(goSource, controlsStart, controlsEnd);
  const positiveCall = 'inner, innerErr := checkedDiagnosticFailure("native helper-read primary", planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: parsedDiagnostic, cause: diagnosticPrimaryCause}))';
  if (controlsRegion.split(positiveCall).length !== 2) throw new Error('checked positive diagnostic constructor anchor is not unique');
  const uncheckedPositive = goSource.replace(controlsRegion, controlsRegion.replace(positiveCall,
    'inner := planBrokerCPUFailureAt(planBrokerCPUStageMatrixCase, planBrokerCPUReasonChildHolderHelperRead, string(planBrokerCPUControlWatchdogNative), &planBrokerCPUHolderReadDiagnosticFailure{diagnostic: parsedDiagnostic, cause: diagnosticPrimaryCause})'));
  let uncheckedReason = '';
  try { validatePureDiagnosticControlSource(verifierSource, uncheckedPositive); } catch (error) { uncheckedReason = String(error?.message ?? error); }
  if (!uncheckedReason.includes('positive diagnostic primary must be concretely checked before diagnostic attachment or alias assertions')) {
    throw new Error(`pure diagnostic source control missed unchecked positive constructor result: ${uncheckedReason || 'accepted'}`);
  }
  const mutateGoTest = (before, after, label) => {
    if (goRegion.split(before).length !== 2) throw new Error(`pure diagnostic Go mutation anchor is not unique: ${label}`);
    reject(verifierSource, goSource.replace(goRegion, goRegion.replace(before, after)), label);
  };
  mutateGoTest(
    'if err := verifyPlanBrokerCPUFailureMarkerControls(); err != nil {',
    'if err := nil; err != nil {', 'omitted existing in-memory control call');
  mutateGoTest(
    't.Fatalf("%s: %v", planBrokerCPUFailureMarkerControlAssertion, err)',
    't.Errorf("%v", err)', 'omitted decisive assertion marker');

  const wholeBlockEdit = "source, [[diagnosticBlock, '\\t// omitted diagnostic attachment by compiled control']]";
  const attachmentOnlyEdit = "source, '\\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)'";
  if (verifierSource.split(wholeBlockEdit).length !== 2) throw new Error('compile-valid whole-block source control anchor is not unique');
  let attachmentRegressionRejected = false;
  try { validatePureDiagnosticControlSource(verifierSource.replace(wholeBlockEdit, attachmentOnlyEdit), goSource); } catch { attachmentRegressionRejected = true; }
  if (!attachmentRegressionRejected) throw new Error('pure diagnostic source control accepted regression to attachment-only compiled mutant replacement');

  const expectedOrder = 'pure diagnostic controls must run positive-first and both negatives before';
  const mutateMode = (source, mode, mutate) => {
    const start = 'function withPrivateBinary(mode) {';
    const end = '\nconst recoveryPolicyTests = [';
    const region = uniqueSourceRegion(source, start, end);
    const reconcileStart = region.indexOf("} else if (mode === '--mode=reconcile') {");
    const cpuStart = region.indexOf("} else {\n      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'", reconcileStart);
    const modeStart = mode === 'reconcile' ? reconcileStart : cpuStart;
    const modeEnd = mode === 'reconcile' ? cpuStart : region.indexOf('\n    }\n  } finally {', cpuStart);
    if (modeStart < 0 || modeEnd <= modeStart) throw new Error(`pure diagnostic source mode region is missing: ${mode}`);
    const branch = region.slice(modeStart, modeEnd);
    const changed = mutate(branch);
    if (changed === branch) throw new Error(`pure diagnostic mode mutation did not change ${mode}`);
    const mutatedRegion = region.slice(0, modeStart) + changed + region.slice(modeEnd);
    return source.replace(region, mutatedRegion);
  };
  const validateOrderMutation = (mutantVerifier, label) => {
    let reason = '';
    try { validatePureDiagnosticControlSource(mutantVerifier, goSource); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(expectedOrder)) throw new Error(`pure diagnostic source control missed ${label}: ${reason || 'accepted'}`);
  };
  for (const mode of ['reconcile', 'cpu-sequence']) {
    const positive = `executeInventory(binary, ['TestPlanBrokerCPUFailureMarkerControlsPure'], 60, false);`;
    const negative = `verifyCompiledHolderDiagnosticMutants(temp, '${mode}');`;
    const descriptorPositive = `executeInventory(binary, ['TestPlanBrokerCPUDescriptorGuardControls'], 60, false);`;
    const descriptorNegative = `verifyCompiledDescriptorGuardMutants(temp, '${mode}');`;
    const fixture = 'const output = executeInventory(binary, selected, 240, true);';
    const originalOrder = `${positive}\n      ${descriptorPositive}\n      ${negative}\n      ${descriptorNegative}\n      ${fixture}`;
    const missingPositive = mutateMode(verifierSource, mode, (branch) => {
      if (branch.split(positive).length !== 2) throw new Error(`positive call anchor is not unique: ${mode}`);
      return branch.replace(positive, '// omitted pure diagnostic positive');
    });
    validateOrderMutation(missingPositive, `omitted ${mode} positive call`);
    const missingNegative = mutateMode(verifierSource, mode, (branch) => {
      if (branch.split(negative).length !== 2) throw new Error(`negative call anchor is not unique: ${mode}`);
      return branch.replace(negative, '// omitted pure diagnostic mutants');
    });
    validateOrderMutation(missingNegative, `omitted ${mode} compiled mutants`);
    const movedAfterFixture = mutateMode(verifierSource, mode, (branch) => {
      if (branch.split(originalOrder).length !== 2) throw new Error(`complete control order anchor is not unique: ${mode}`);
      const moved = `${descriptorPositive}\n      ${descriptorNegative}\n      ${fixture}\n      ${positive}\n      ${negative}`;
      const changed = branch.replace(originalOrder, moved);
      if (changed.split(fixture).length !== 2 || changed.split(descriptorPositive).length !== 2 ||
          changed.split(descriptorNegative).length !== 2 || changed.indexOf(positive) <= changed.indexOf(fixture) ||
          changed.indexOf(negative) <= changed.indexOf(fixture)) {
        throw new Error(`moved ${mode} mutation did not retain each descriptor call and the single existing fixture`);
      }
      return changed;
    });
    validateOrderMutation(movedAfterFixture, `moved ${mode} pure controls after effectful inventory`);
  }
}

function selfTestInventory() {
  exactInventory('=== RUN   TestA\n--- PASS: TestA (0.00s)\n', ['TestA']);
  const bad = [
    '--- PASS: TestA (0.00s)\n',
    '=== RUN TestA\n=== RUN TestA\n--- PASS: TestA (0.00s)\n',
    '=== RUN TestA\n--- SKIP: TestA (0.00s)\n',
    '=== RUN TestA\n--- FAIL: TestA (0.00s)\n',
    '--- PASS: TestA (0.00s)\n=== RUN TestA\n',
    '=== RUN TestA\n--- PASS: TestA\n',
    '=== RUN TestA\n=== RUN TestB\n--- PASS: TestA (0.00s)\n--- PASS: TestB (0.00s)\n',
  ];
  for (const output of bad) {
    let rejected = false;
    try { exactInventory(output, ['TestA']); } catch { rejected = true; }
    if (!rejected) throw new Error('exact inventory parser accepted a negative control');
  }
}
selfTestInventory();

const diagnosticTestFiles = [
  'internal/nodeagent/checkpoint_plan_rotation_test.go',
  'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_test.go',
  'internal/nodeagent/checkpoint_lifecycle_broker_linux_test.go',
  'internal/nodeagent/commands_test.go',
  'internal/wsproto/messages_test.go',
];
const reviewedInventoryTestNames = new Set([
  'TestPlanRelaunchWireIsCatalogTypedAndRejectsGenericAuthority',
  'TestCheckpointPlanCatalogRequiresCanonicalApprovedV2Bytes',
  'TestPlanRelaunchSharesStopFenceAndRequiresTerminalPriorStep',
  'TestPlanRelaunchReceiptRequiresExactOriginalAndFreshIdentity',
  'TestPlanRelaunchReceiptReconcilesOnlyPreviouslyAcceptedExpiredIntent',
  'TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart',
  'TestPlanRelaunchQueryTimeWindowIsBounded',
  'TestPlanBrokerUnitParserRequiresCompleteFixedProperties',
  'TestPlanBrokerJobParserUsesExactUnitIdentity',
  'TestPlanBrokerRequestHalfCloseUnixStream',
  'TestPlanBrokerRequestHalfCloseRejectsWriteFaults',
  'TestPlanBrokerCPUFailureMarkerControlsPure',
  'TestCheckpointPlanRelaunchCPULifecycleSequence',
  'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect',
]);
const maxFailureCaptureBytes = 8 * 1024 * 1024;
const maxFailureDiagnosticBytes = 8192;
const maxFailureOwners = 16;
const maxFailureSitesPerOwner = 4;
const maxFailureLineBytes = 64 * 1024;

function loadDiagnosticTestSources() {
  return new Map(diagnosticTestFiles.map((relative) => {
    const source = readFileSync(path.join(root, relative), 'utf8');
    const lineCount = source.split(/\r?\n/).length - (source.endsWith('\n') ? 1 : 0);
    return [relative, { basename: path.posix.basename(relative), lineCount, source }];
  }));
}

function classifyOptInTestFailureSites(output, expected) {
  const unavailable = 'test_sites=unavailable';
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > maxFailureCaptureBytes ||
      !Array.isArray(expected) || expected.length === 0 || expected.length > 32 ||
      expected.some((name) => typeof name !== 'string' || !reviewedInventoryTestNames.has(name)) ||
      new Set(expected).size !== expected.length) return unavailable;

  const sourceFiles = loadDiagnosticTestSources();
  const expectedSet = new Set(expected);
  const owners = new Map();
  const nested = new Map();
  const sourceRefs = [];
  let openOwner = null;
  const lines = output.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex++) {
    const line = lines[lineIndex];
    if (Buffer.byteLength(line, 'utf8') > maxFailureLineBytes) return unavailable;
    const trimmed = line.trimStart();
    if (trimmed.startsWith('===') || trimmed.startsWith('---')) {
      let event;
      const run = line.match(/^=== RUN   (Test[A-Za-z0-9_]+(?:\/[A-Za-z0-9_.-]+)*)$/);
      const outcome = line.match(/^--- (PASS|FAIL|SKIP): (Test[A-Za-z0-9_]+(?:\/[A-Za-z0-9_.-]+)*) \(([0-9]+(?:\.[0-9]+)?s)\)$/);
      if (run) event = { kind: 'RUN', name: run[1] };
      else if (outcome) event = { kind: outcome[1], name: outcome[2] };
      else return unavailable;

      const slash = event.name.indexOf('/');
      const ownerName = slash < 0 ? event.name : event.name.slice(0, slash);
      if (!expectedSet.has(ownerName)) return unavailable;
      if (slash < 0) {
        if (event.kind === 'RUN') {
          if (openOwner || owners.has(ownerName)) return unavailable;
          openOwner = { name: ownerName, start: lineIndex, end: null, outcome: null };
          owners.set(ownerName, openOwner);
        } else {
          if (!openOwner || openOwner.name !== ownerName || openOwner.outcome !== null ||
              [...nested.values()].some((child) => child.owner === ownerName && child.outcome === null)) return unavailable;
          openOwner.end = lineIndex;
          openOwner.outcome = event.kind;
          openOwner = null;
        }
      } else {
        if (!openOwner || openOwner.name !== ownerName) return unavailable;
        const previous = nested.get(event.name);
        if (event.kind === 'RUN') {
          if (previous) return unavailable;
          nested.set(event.name, { owner: ownerName, start: lineIndex, end: null, outcome: null });
        } else {
          if (!previous || previous.outcome !== null || previous.start >= lineIndex) return unavailable;
          previous.end = lineIndex;
          previous.outcome = event.kind;
        }
      }
    }

    const matches = [...line.matchAll(/(?:^|[\s(])([A-Za-z0-9_./\\-]+_test\.go):([0-9]+)(?::|\s+\+|$)/g)];
    const goTokenCount = [...line.matchAll(/\.go\b/g)].length;
    if (goTokenCount !== matches.length) return unavailable;
    if (matches.length > 1) return unavailable;
    if (matches.length === 1) {
      const rawPath = matches[0][1].replaceAll('\\', '/');
      if (rawPath.split('/').some((part) => part === '.' || part === '..')) return unavailable;
      const sourceEntry = [...sourceFiles.entries()].find(([relative, details]) =>
        rawPath === relative || rawPath === details.basename || rawPath.endsWith(`/${relative}`));
      if (!sourceEntry) return unavailable;
      const lineText = matches[0][2];
      const sourceLine = Number(lineText);
      if (!Number.isSafeInteger(sourceLine) || sourceLine < 1 || String(sourceLine) !== lineText ||
          sourceLine > sourceEntry[1].lineCount) return unavailable;
      sourceRefs.push({ lineIndex, basename: sourceEntry[1].basename, sourceLine });
    }
  }

  if (openOwner || owners.size !== expected.length || [...nested.values()].some((child) => child.outcome === null)) return unavailable;
  for (const ownerName of expected) {
    const owner = owners.get(ownerName);
    if (!owner || owner.end === null || (owner.outcome !== 'PASS' && owner.outcome !== 'FAIL')) return unavailable;
  }
  const failedOwners = [...owners.values()].filter((owner) => owner.outcome === 'FAIL').map((owner) => owner.name);
  if (failedOwners.length === 0 || failedOwners.length > maxFailureOwners) return unavailable;
  if ([...nested.values()].some((child) => child.outcome === 'FAIL' && owners.get(child.owner).outcome !== 'FAIL')) return unavailable;
  const sitesByOwner = new Map(failedOwners.map((name) => [name, new Set()]));
  for (const site of sourceRefs) {
    const matchingOwners = [...owners.values()].filter((owner) => owner.start < site.lineIndex && site.lineIndex < owner.end);
    if (matchingOwners.length !== 1) return unavailable;
    const owner = matchingOwners[0];
    if (owner.outcome === 'FAIL') {
      const siteKey = `${site.basename}:${site.sourceLine}`;
      const siteSet = sitesByOwner.get(owner.name);
      if (siteSet.has(siteKey)) return unavailable;
      siteSet.add(siteKey);
      if (siteSet.size > maxFailureSitesPerOwner) return unavailable;
    }
  }
  if (failedOwners.some((name) => sitesByOwner.get(name).size === 0)) return unavailable;
  const summary = `test_sites=${failedOwners.map((name) => `${name}=${[...sitesByOwner.get(name)].join(',')}`).join(';')}`;
  return Buffer.byteLength(summary, 'utf8') <= maxFailureDiagnosticBytes ? summary : unavailable;
}

function validateBrokerServiceUnit(source) {
  const lines = source.split(/\r?\n/);
  const values = new Map();
  for (const key of ['User', 'Group', 'RuntimeDirectory', 'RuntimeDirectoryMode', 'RestrictAddressFamilies', 'CapabilityBoundingSet', 'AmbientCapabilities']) {
    const matches = lines.filter((line) => line.startsWith(`${key}=`));
    if (matches.length !== 1) throw new Error(`broker service must declare exactly one ${key}`);
    values.set(key, matches[0].slice(key.length + 1));
  }
  if (lines.some((line) => line.startsWith('RuntimeDirectoryGroup=')) ||
      values.get('User') !== 'root' || values.get('Group') !== 'vram-governor' ||
      values.get('RuntimeDirectory') !== 'vram-governor-plan' || values.get('RuntimeDirectoryMode') !== '0750' ||
      values.get('RestrictAddressFamilies') !== 'AF_UNIX AF_INET AF_INET6' ||
      values.get('CapabilityBoundingSet') !== '' || values.get('AmbientCapabilities') !== '' ||
      source.includes('CAP_SYS_PTRACE')) {
    throw new Error('broker service privilege/network posture differs from its fixed local-only contract');
  }
}

function selfTestBrokerServiceUnit() {
  const valid = '[Service]\nUser=root\nGroup=vram-governor\nRuntimeDirectory=vram-governor-plan\nRuntimeDirectoryMode=0750\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nCapabilityBoundingSet=\nAmbientCapabilities=\n';
  validateBrokerServiceUnit(valid);
  for (const mutant of [
    valid.replace('AF_INET AF_INET6', 'AF_INET'),
    valid.replace('CapabilityBoundingSet=\n', 'CapabilityBoundingSet=CAP_SYS_PTRACE\n'),
    valid.replace('RuntimeDirectoryMode=0750', 'RuntimeDirectoryGroup=vram-governor\nRuntimeDirectoryMode=0750'),
  ]) {
    let rejected = false;
    try { validateBrokerServiceUnit(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error('broker service contract parser accepted an unsafe negative control');
  }
}
selfTestBrokerServiceUnit();
validateBrokerServiceUnit(readFileSync(path.join(root, 'deploy/checkpoint-lifecycle-broker.service'), 'utf8'));

function validateFreezeManifest(manifest, requireRootReview = false) {
  const reject = (code) => { throw new Error(`freeze:${code}`); };
  if (!manifest || typeof manifest !== 'object' || !Array.isArray(manifest.files)) reject('shape');
  if (manifest.reviewStatus !== 'pending-root-review' && manifest.reviewStatus !== 'root-reviewed') reject('review-status');
  if (requireRootReview && manifest.reviewStatus !== 'root-reviewed') reject('not-root-reviewed');
  const entries = manifest.files;
  const paths = entries.map((entry) => entry?.Path);
  if (new Set(paths).size !== paths.length) reject('duplicate-path');
  if (paths.length !== frozenPaths.length) reject(paths.some((item) => !frozenPaths.includes(item)) ? 'extra-path' : 'missing-path');
  if (JSON.stringify([...paths].sort()) !== JSON.stringify(frozenPaths)) reject(paths.some((item) => !frozenPaths.includes(item)) ? 'substitute-path' : 'path-set');
  for (const entry of entries) {
    if (!Number.isSafeInteger(entry.Bytes) || entry.Bytes < 0 || typeof entry.Sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(entry.Sha256)) reject('pin-shape');
    const raw = readFileSync(path.join(root, entry.Path));
    const digest = createHash('sha256').update(raw).digest('hex');
    if (raw.length !== entry.Bytes || digest !== entry.Sha256) reject('stale-pin');
  }
  return true;
}

function readCurrentFreeze() {
  return JSON.parse(readFileSync(freezePath, 'utf8'));
}

function requireReviewedCurrentFreeze() {
  validateFreezeManifest(readCurrentFreeze(), true);
}

function declarationBody(source, signature, nextSignature) {
  const startNeedle = `\n${signature}`;
  const endNeedle = `\n${nextSignature}`;
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (start < 0 || end <= start || source.indexOf(startNeedle, start + startNeedle.length) >= 0) {
    throw new Error(`source declaration is missing, ambiguous, or unbounded: ${signature}`);
  }
  return source.slice(start + 1, end + 1);
}

function uniqueSourceRegion(source, startDeclaration, nextDeclaration) {
  const startNeedle = `\n${startDeclaration}`;
  const endNeedle = `\n${nextDeclaration}`;
  const start = source.indexOf(startNeedle);
  const end = source.indexOf(endNeedle, start + startNeedle.length);
  if (start < 0 || end <= start || source.indexOf(startNeedle, start + startNeedle.length) >= 0) {
    throw new Error(`source declaration is missing, ambiguous, or unbounded: ${startDeclaration}`);
  }
  return source.slice(start + 1, end + 1);
}

const expectedCPUFixtureTree = [
  ['run', '0o750'], ['etc', '0o755'], ['var', '0o711'], ['var/private', '0o700'],
  ['var/public', '0o755'], ['var/public/receipts', '0o750'], ['var/stop-private', '0o700'],
  ['var/stop-public', '0o750'], ['var/stop-public/receipts', '0o750'], ['var/node', '0o700'],
  ['var/events', '0o755'], ['var/custody', '0o700'], ['var/snapshots', '0o700'], ['models', '0o755'],
];

function validateCPUFixtureTreeSource(source) {
  const body = uniqueSourceRegion(source, 'func createPlanBrokerCPUFixtureTree(paths checkpointPlanBrokerPaths) error {', 'func writePlanBrokerCPUFile(');
  const literalMatch = body.match(/entries := \[\]struct \{\s*relative string\s*mode\s+os\.FileMode\s*\}\s*\{([\s\S]*?)\n\t\}/);
  if (!literalMatch || body.includes('map[string]os.FileMode') || body.includes('MkdirAll')) throw new Error('fixture tree must use its fixed literal slice and nonrecursive directory creation');
  const entries = [...literalMatch[1].matchAll(/\{"([^"\n]+)",\s*(0o[0-7]+)\}/g)].map((match) => [match[1], match[2]]);
  if (JSON.stringify(entries) !== JSON.stringify(expectedCPUFixtureTree)) throw new Error('fixture tree entry inventory, order, uniqueness, or modes differ from the fixed parent-first contract');
  const order = new Map(entries.map(([relative], index) => [relative, index]));
  if (order.size !== 14) throw new Error('fixture tree has duplicate directory entries');
  for (const [relative] of entries) {
    const components = relative.split('/');
    let parent = '';
    for (const component of components.slice(0, -1)) {
      parent = parent ? `${parent}/${component}` : component;
      if (!order.has(parent) || order.get(parent) >= order.get(relative)) throw new Error(`fixture parent ${parent} does not precede ${relative}`);
    }
  }
  const loopAt = body.indexOf('for _, entry := range entries {');
  const loop = body.slice(loopAt);
  const mkdirAt = loop.indexOf('os.Mkdir(path, entry.mode)');
  const chownAt = loop.indexOf('os.Chown(path, uid, gid)');
  const chmodAt = loop.indexOf('os.Chmod(path, entry.mode)');
  const normalizedLoop = loop.replace(/\s+/g, ' ');
  if (loopAt < 0 || mkdirAt < 0 || chownAt <= mkdirAt || chmodAt <= chownAt ||
      !loop.includes('filepath.FromSlash(entry.relative)') ||
      !normalizedLoop.includes('uid, gid := 0, 0') ||
      !normalizedLoop.includes('if entry.relative == "var/node" { uid, gid = int(paths.NodeUID), int(paths.NodeGID) }') ||
      !normalizedLoop.includes('if strings.HasPrefix(entry.relative, "var/public/receipts") || strings.HasPrefix(entry.relative, "var/stop-public") || entry.relative == "run" { gid = int(paths.NodeGID) }')) {
    throw new Error('fixture tree lost per-entry Mkdir/Chown/Chmod or its exact UID/GID branches');
  }
  return true;
}

function selfTestCPUFixtureTreeSource(source) {
  validateCPUFixtureTreeSource(source);
  const reject = (mutant, label) => {
    let rejected = false;
    try { validateCPUFixtureTreeSource(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`fixture tree source control accepted ${label}`);
  };
  reject(source.replace('{"var", 0o711}, {"var/private", 0o700}', '{"var/private", 0o700}, {"var", 0o711}'), 'child-before-parent ordering');
  reject(source.replace('{"etc", 0o755}, ', ''), 'omitted directory');
  reject(source.replace('{"var/events", 0o755}', '{"var/custody", 0o700}'), 'duplicate directory');
  reject(source.replace('{"run", 0o750}', '{"run", 0o751}'), 'mode drift');
  reject(source.replace('uid, gid = int(paths.NodeUID), int(paths.NodeGID)', 'uid, gid = 0, 0'), 'node ownership drift');
  reject(source.replace('gid = int(paths.NodeGID)', 'gid = 0'), 'group ownership drift');
  reject(source.replace('strings.HasPrefix(entry.relative, "var/public/receipts") || strings.HasPrefix(entry.relative, "var/stop-public")', 'strings.HasPrefix(entry.relative, "var/public/receipts") && strings.HasPrefix(entry.relative, "var/stop-public")'), 'ownership branch predicate drift');
}

function validateBrokerRequestTransportSource(broker, brokerTest, verifier) {
  const writer = uniqueSourceRegion(broker, 'func writeCheckpointPlanBrokerRequest(conn checkpointPlanBrokerRequestHalfCloser, request []byte) error {', 'func invokeCheckpointPlanBroker(');
  const invoke = uniqueSourceRegion(broker, 'func invokeCheckpointPlanBroker(ctx context.Context, paths checkpointPlanBrokerPaths, request []byte) ([]byte, error) {', 'func checkpointPlanBrokerServerPeer(');
  const positive = uniqueSourceRegion(brokerTest, 'func TestPlanBrokerRequestHalfCloseUnixStream(t *testing.T) {', 'func TestPlanBrokerRequestHalfCloseRejectsWriteFaults(');
  const fault = uniqueSourceRegion(brokerTest, 'func TestPlanBrokerRequestHalfCloseRejectsWriteFaults(t *testing.T) {', 'func TestPlanBrokerUnitParserRequiresCompleteFixedProperties(');
  const require = (condition, label) => { if (!condition) throw new Error(`broker request transport source is incomplete: ${label}`); };
  const rootOpenFailure = positive.slice(positive.indexOf('rootHandle, err := os.Open(root)'), positive.indexOf('rootInfo, err := rootHandle.Stat()'));
  const rootIdentityFailure = positive.slice(positive.indexOf('rootInfo, err := rootHandle.Stat()'), positive.indexOf('socket := filepath.Join(root, "request.sock")'));
  require(rootOpenFailure.includes('preserving unique private fixture directory') && rootIdentityFailure.includes('preserving unique private fixture directory') &&
    !rootOpenFailure.includes('os.Remove(') && !rootIdentityFailure.includes('os.Remove('),
  'pre-hold MkdirTemp uncertainty is visibly retained without attempting deletion');
  const interfaceStart = broker.indexOf('\ntype checkpointPlanBrokerRequestHalfCloser interface {');
  const interfaceEnd = broker.indexOf('\nfunc writeCheckpointPlanBrokerRequest(', interfaceStart);
  const halfCloser = interfaceStart < 0 || interfaceEnd <= interfaceStart ? '' : broker.slice(interfaceStart, interfaceEnd);
  const writeAt = writer.indexOf('n, err := conn.Write(frame)');
  const shortAt = writer.indexOf('if n != len(frame) {');
  const closeAt = writer.indexOf('conn.CloseWrite()');
  require(halfCloser.includes('Write([]byte) (int, error)') && halfCloser.includes('CloseWrite() error') && broker.indexOf('\ntype checkpointPlanBrokerRequestHalfCloser interface {', interfaceStart + 1) < 0, 'request writer requires an exact half-close interface');
  require(writer.includes('len(request) >= checkpointPlanRelaunchMaxFrame') && writer.includes('make([]byte, len(request)+1)') && writer.includes('copy(frame, request)') && writer.includes("frame[len(request)] = '\\n'"), 'bounded complete request frame plus newline');
  require(writeAt >= 0 && shortAt > writeAt && closeAt > shortAt && writer.includes('return io.ErrShortWrite') && writer.includes('return fmt.Errorf("fixed plan broker request half-close failed: %w", err)'), 'full write is verified before half-close and errors fail closed');
  require(invoke.includes('len(request) >= checkpointPlanRelaunchMaxFrame') && invoke.includes('if err := writeCheckpointPlanBrokerRequest(conn, request); err != nil {'), 'client bounds and uses the request half-close helper');
  require(invoke.indexOf('writeCheckpointPlanBrokerRequest(conn, request)') < invoke.indexOf('io.ReadAll(io.LimitReader(conn, checkpointPlanRelaunchMaxFrame+1))'), 'request EOF is sent before reply read');
  for (const token of ['os.MkdirTemp("", "plan-broker-transport-")', 'rootHandle, err := os.Open(root)', 'rootInfo, err := rootHandle.Stat()', 'preserving unique private fixture directory', 'type serverCloseResult struct {', 'var serverCloseOutcome chan serverCloseResult', 'serverCloseOutcome = make(chan serverCloseResult, 1)', 'os.SameFile(rootInfo, currentRoot)', 'net.ListenUnix("unix"', 'listener.SetUnlinkOnClose(false)', 'socketInfo, err = os.Lstat(socket)', 'listener.AcceptUnix()', 'server.SetDeadline(', 'client.SetDeadline(', 'io.ReadAll(io.LimitReader(server, checkpointPlanRelaunchMaxFrame+1))', 'writeCheckpointPlanBrokerRequest(client, []byte("ordinary bounded request"))', 'io.ReadAll(io.LimitReader(client, checkpointPlanRelaunchMaxFrame+1))', 'ordinary request did not receive response after half-close', 'response := []byte("{\\"accepted\\":true}\\n")', 'serverDone', 'serverClosed', 'time.After(5 * time.Second)', 'os.SameFile(socketInfo, currentSocket)', 'os.Remove(socket)', 'os.ReadDir(root)', 'os.Remove(root)']) require(positive.includes(token), `bounded real Unix-stream fixture/cleanup proof ${token}`);
  require(!positive.includes('t.TempDir()') && !positive.includes('defer client.Close()') && !positive.includes('SetUnlinkOnClose(true)') && !positive.includes('RemoveAll(') && !positive.includes('MkdirAll('), 'fixture root is manually held and cleanup is nonrecursive');
  const cleanupStart = positive.indexOf('cleanup := func() error {');
  const cleanupEnd = positive.indexOf('\n\tdefer func() {', cleanupStart);
  const cleanup = cleanupStart < 0 || cleanupEnd <= cleanupStart ? '' : positive.slice(cleanupStart, cleanupEnd);
  require(cleanup.includes('closeState = "unknown"') && cleanup.includes('closeState = "not-created"') && cleanup.includes('closeState = "close-failed"'),
    'accepted-server outcome explicitly distinguishes not-created, unknown, and failed-close states');
  const cleanupNeedles = [
    'listener.Close()', 'client.Close()', 'case <-serverClosed:', 'case <-time.After(5 * time.Second):',
    'closeState := "not-created"', 'if serverCloseOutcome != nil', 'case outcome, ok := <-serverCloseOutcome:',
    'if closeState == "unknown" || closeState == "close-failed"',
    'os.Lstat(root)', 'os.Lstat(socket)', 'os.SameFile(socketInfo, currentSocket)', 'os.Remove(socket)',
    'os.Lstat(socket)', 'os.ReadDir(root)', 'os.Remove(root)', 'os.Lstat(root)',
  ];
  let cleanupCursor = 0;
  const cleanupOrder = cleanupNeedles.map((needle) => {
    const at = cleanup.indexOf(needle, cleanupCursor);
    cleanupCursor = at < 0 ? cleanupCursor : at + needle.length;
    return at;
  });
  require(cleanupOrder.every((at) => at >= 0), 'owned listener/client close, fixed join, identity checks, exact socket/root removal and absence confirmation are ordered');
  require(cleanup.includes('if err := listener.Close(); err != nil') && cleanup.includes('if err := client.Close(); err != nil') && cleanup.includes('if cleanupErr != nil {'), 'owned listener/client close errors fail closed and prevent cleanup credit');
  require(positive.includes('defer func() {\n\t\tif !cleanupAttempted {\n\t\t\tif err := cleanup(); err != nil {') &&
    positive.includes('cleanupAttempted = true'), 'all post-root-hold early failures flow through the bounded cleanup and close-outcome guard');
  const heldRootAt = positive.indexOf('if currentRoot, err := os.Lstat(root); err != nil || !os.SameFile(rootInfo, currentRoot) {');
  const listenerCreateAt = positive.indexOf('net.ListenUnix("unix"');
  require(heldRootAt >= 0 && listenerCreateAt > heldRootAt, 'held private root identity is rechecked before socket creation');
  const goroutineStart = positive.indexOf('go func() {');
  const goroutineEnd = positive.indexOf('\n\t}()', goroutineStart);
  const serverGoroutine = goroutineStart < 0 || goroutineEnd <= goroutineStart ? '' : positive.slice(goroutineStart, goroutineEnd);
  const serverCleanupStart = serverGoroutine.indexOf('defer func() {');
  const serverCleanupEnd = serverGoroutine.indexOf('\n\t\t}()', serverCleanupStart);
  const serverCleanup = serverCleanupStart < 0 || serverCleanupEnd <= serverCleanupStart ? '' : serverGoroutine.slice(serverCleanupStart, serverCleanupEnd);
  const acceptFailureStart = serverGoroutine.indexOf('if acceptErr != nil {');
  const acceptFailureEnd = serverGoroutine.indexOf('\n\t\t}', acceptFailureStart + 1);
  const acceptFailure = acceptFailureStart < 0 || acceptFailureEnd <= acceptFailureStart ? '' : serverGoroutine.slice(acceptFailureStart, acceptFailureEnd);
  require(acceptFailure.includes('serverCloseOutcome <- serverCloseResult{known: true, accepted: false}') &&
    acceptFailure.indexOf('accepted: false') < acceptFailure.indexOf('serverDone <- serverResult{err: acceptErr}') &&
    acceptFailure.indexOf('serverDone <- serverResult{err: acceptErr}') < acceptFailure.indexOf('close(serverClosed)'),
  'failed Accept publishes a known not-created outcome before the completion signal');
  const serverCloseAt = serverCleanup.indexOf('closeErr := server.Close()');
  const outcomeAt = serverCleanup.indexOf('serverCloseOutcome <- serverCloseResult{known: true, accepted: true, err: closeErr}');
  const joinedCloseAt = serverCleanup.indexOf('result.err = errors.Join(result.err, closeErr)');
  require(serverCloseAt >= 0 && outcomeAt > serverCloseAt && joinedCloseAt > outcomeAt &&
    serverCleanup.indexOf('serverDone <- result') > joinedCloseAt && serverCleanup.indexOf('close(serverClosed)') > serverCleanup.indexOf('serverDone <- result'),
  'accepted-server close outcome is independently published and joined before result/completion publication');
  require(cleanup.indexOf('case <-serverClosed:') < cleanup.indexOf('closeState := "not-created"') &&
    cleanup.indexOf('closeState := "not-created"') < cleanup.indexOf('if closeState == "unknown" || closeState == "close-failed"') &&
    cleanup.indexOf('if closeState == "unknown" || closeState == "close-failed"') < cleanup.indexOf('os.Lstat(socket)') &&
    cleanup.indexOf('if closeState == "unknown" || closeState == "close-failed"') < cleanup.indexOf('os.Remove(socket)') &&
    cleanup.includes('return errors.New("bounded Unix accepted-server close outcome is unknown; preserving fixture")') &&
    cleanup.includes('return errors.New("bounded Unix accepted-server close outcome was not published; preserving fixture")') &&
    cleanup.includes('if !outcome.accepted {\n\t\t\t\t\tcloseState = "not-created"') &&
    cleanup.includes('closeState = "close-failed"'),
  'every joined cleanup distinguishes not-created from unknown and rejects failed/unknown close before socket or root removal');
  require(positive.includes('server.SetDeadline(time.Now().Add(2 * time.Second))') && positive.includes('client.SetDeadline(time.Now().Add(2 * time.Second))') && (positive.match(/SetDeadline\(time\.Now\(\)\.Add\(2 \* time\.Second\)\)/g) ?? []).length === 2, 'original exact two-second socket deadlines remain unchanged');
  require(positive.includes('len(frame) > checkpointPlanRelaunchMaxFrame') && positive.includes('string(frame) != "ordinary bounded request\\n"') && positive.includes('case <-time.After(2 * time.Second):'), 'positive checks exact bounded frame and settlement');
  for (const token of ['writeErr', 'writeLimit', 'closeErr', 'errors.Is(err, writeFailure)', 'errors.Is(err, io.ErrShortWrite)', 'errors.Is(err, closeFailure)', 'writeConn.closeCalls != 0', 'shortConn.closeCalls != 0', 'closeConn.closeCalls != 1', 'string(closeConn.written) != "bounded\\n"', 'completeConn.closeCalls != 1']) require(fault.includes(token), `short-write/CloseWrite fault control ${token}`);
  const verifyMutant = uniqueSourceRegion(verifier, 'function verifyCompiledRequestHalfCloseMutant(temp, mode) {', 'function verifyCompiledHolderDiagnosticMutants(');
  require(verifyMutant.includes("if (mode !== 'reconcile' && mode !== 'cpu-sequence')") && verifyMutant.includes("'mutant-request-missing-closewrite-' + mode") && verifyMutant.includes('conn.CloseWrite()') && verifyMutant.includes('TestPlanBrokerRequestHalfCloseUnixStream') && verifyMutant.includes('ordinary request did not receive response after half-close') && (verifyMutant.match(/compileBehavioralMutant\(/g) ?? []).length === 1, 'compiled missing-CloseWrite mutant must use the bounded positive Unix test');
  const rejectMutant = (mutant, label) => {
    let rejected = false;
    try { validateBrokerRequestTransportSource(mutant, brokerTest, verifier); } catch { rejected = true; }
    if (!rejected) throw new Error(`broker request transport source mutant was accepted: ${label}`);
  };
  const replaceOnce = (source, before, after) => {
    if (source.split(before).length !== 2) throw new Error('broker transport mutation anchor is not exact-once');
    return source.replace(before, after);
  };
  rejectMutant(replaceOnce(broker, '\tif n != len(frame) {\n\t\treturn io.ErrShortWrite\n\t}', ''), 'unchecked short write');
  rejectMutant(replaceOnce(broker, '\tif err := conn.CloseWrite(); err != nil {\n\t\treturn fmt.Errorf("fixed plan broker request half-close failed: %w", err)\n\t}', ''), 'missing CloseWrite');
  const brokerTestMutant = replaceOnce(brokerTest, 'errors.Is(err, closeFailure)', 'errors.Is(err, writeFailure)');
  let missingFaultRejected = false;
  try { validateBrokerRequestTransportSource(broker, brokerTestMutant, verifier); } catch { missingFaultRejected = true; }
  if (!missingFaultRejected) throw new Error('broker transport source controls accepted a lost CloseWrite error assertion in the complete brokerTest input');
  const rejectTestMutant = (mutant, label) => {
    let rejected = false;
    try { validateBrokerRequestTransportSource(broker, mutant, verifier); } catch { rejected = true; }
    if (!rejected) throw new Error(`broker Unix fixture source mutant was accepted: ${label}`);
  };
  rejectTestMutant(replaceOnce(brokerTest, 'case <-serverClosed:\n\t\tcase <-time.After(5 * time.Second):', 'case <-time.After(5 * time.Second):'), 'missing server completion join');
  rejectTestMutant(replaceOnce(brokerTest, 'serverCloseOutcome <- serverCloseResult{known: true, accepted: true, err: closeErr}', 'close(serverClosed)\n\t\t\tserverCloseOutcome <- serverCloseResult{known: true, accepted: true, err: closeErr}'), 'completion signal before accepted server close outcome');
  rejectTestMutant(replaceOnce(brokerTest, 'result.err = errors.Join(result.err, closeErr)', 'if result.err == nil { result.err = closeErr }'), 'protocol error suppresses independent accepted-server close error');
  rejectTestMutant(replaceOnce(brokerTest, 'serverCloseOutcome <- serverCloseResult{known: true, accepted: true, err: closeErr}', '/* accepted-server close outcome omitted */'), 'missing accepted-server close outcome publication');
  rejectTestMutant(replaceOnce(brokerTest, 'if closeState == "unknown" || closeState == "close-failed" {', 'if false && (closeState == "unknown" || closeState == "close-failed") {'), 'cleanup ignores unknown or failed accepted-server close');
  rejectTestMutant(replaceOnce(brokerTest, 'closeState = "unknown"', 'closeState = "not-created"'), 'unknown outcome misreported as not-created');
  rejectTestMutant(replaceOnce(brokerTest, 'serverCloseOutcome <- serverCloseResult{known: true, accepted: false}', 'serverCloseOutcome <- serverCloseResult{known: true, accepted: true}'), 'failed Accept misreported as accepted connection');
  rejectTestMutant(replaceOnce(brokerTest, 'bounded private Unix fixture directory could not be held; preserving unique private fixture directory', 'bounded private Unix fixture directory could not be held'), 'pre-hold uncertain directory not visibly retained');
  rejectTestMutant(replaceOnce(brokerTest, 'os.MkdirTemp("", "plan-broker-transport-")', 't.TempDir()'), 'automatic testing.TempDir cleanup');
  rejectTestMutant(replaceOnce(brokerTest, 'listener.SetUnlinkOnClose(false)', 'listener.SetUnlinkOnClose(true)'), 'listener auto-unlink');
  rejectTestMutant(replaceOnce(brokerTest, 'if currentRoot, err := os.Lstat(root); err != nil || !os.SameFile(rootInfo, currentRoot) {', 'if currentRoot, err := os.Lstat(root); err != nil || !currentRoot.IsDir() {'), 'missing held root identity recheck');
  rejectTestMutant(replaceOnce(brokerTest, 'if err := listener.Close(); err != nil && cleanupErr == nil {', 'if err := listener.Close(); err != nil { _ = err }'), 'ignored listener close failure');
  rejectTestMutant(replaceOnce(brokerTest, 'if err := client.Close(); err != nil && cleanupErr == nil {', 'if err := client.Close(); err != nil { _ = err }'), 'ignored client close failure');
  rejectTestMutant(replaceOnce(brokerTest, 'if err := os.Remove(socket); err != nil {', 'if _, err := os.Lstat(socket); err != nil {'), 'missing exact socket unlink');
  rejectTestMutant(replaceOnce(brokerTest, 'if err := os.Remove(root); err != nil {', 'if _, err := os.Lstat(root); err != nil {'), 'missing nonrecursive root removal');
  return true;
}

function validateTransport12Source(source) {
  const requireText = (region, items, label) => {
    for (const item of items) if (!region.includes(item)) throw new Error(`${label} is missing required source guard: ${item}`);
  };
  const prebind = uniqueSourceRegion(source, 'func prebindPlanBrokerCPUFixtureUnit(paths checkpointPlanBrokerPaths, root string, held os.FileInfo) (string, error) {', 'func planBrokerCPUFixtureUnitIdentity(');
  requireText(prebind, ['filepath.EvalSymlinks(filepath.Dir(root))', 'filepath.EvalSymlinks(os.TempDir())', 'filepath.Clean(parent) != filepath.Clean(temp)', 'os.SameFile(held, current)', 'current.Mode().Perm() != 0o711', 'rootStat.Uid != 0', 'currentStat.Uid != 0', 'paths.NodeUID != 65534', 'paths.NodeGID == 0', 'checkpointPlanBrokerFixtureNameRE.MatchString(filepath.Base(root))', 'paths.fixtureUnit != unit', 'unit == checkpointPlanBrokerUnit'], 'pre-tree private unit binding');
  const identity = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitIdentity(paths checkpointPlanBrokerPaths, unit string) bool {', 'func planBrokerCPUFixtureUnitBound(');
  requireText(identity, ['paths.privateFixture', 'paths.fixtureUnit == filepath.Base(paths.fixtureRoot)+".service"', 'unit == paths.fixtureUnit', 'unit != checkpointPlanBrokerUnit'], 'private fixture unit identity');
  const bound = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitBound(paths checkpointPlanBrokerPaths, unit string) bool {', 'func planBrokerCPUFixtureUnitState(');
  requireText(bound, ['planBrokerCPUFixtureUnitIdentity(paths, unit)', 'checkpointPlanBrokerPrivateFixturePathSet(paths)', 'checkpointPlanBrokerUnitName(paths) == unit'], 'post-tree private unit binding');
  const state = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error) {', 'func createPlanBrokerCPUFixtureTree(');
  requireText(state, ['capturedUnit := paths.fixtureUnit', 'if !planBrokerCPUFixtureUnitBound(paths, capturedUnit)', 'checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", capturedUnit', '"--property=MainPID"', '"--property=InvocationID"', '"--property=ControlGroup"', '"--property=ActiveState"', '"--property=SubState"', 'len(raw) > checkpointUnitMaxOutput', 'raw[len(raw)-1] != \'\\n\'', 'parseCheckpointPlanBrokerUnitState(raw)', 'capturedUnit != paths.fixtureUnit', '!planBrokerCPUFixtureUnitBound(paths, capturedUnit)'], 'explicit private unit-state query');
  const activeObserved = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitStateObserved(', '\nfunc planBrokerCPUFixtureStoppedStateObserved(');
  requireText(activeObserved, ['if capturedUnit != paths.fixtureUnit || !planBrokerCPUFixtureUnitBound(paths, capturedUnit)', 'private fixture binding changed during unit-state query'], 'active-state post-query private unit revalidation');
  if (state.includes('checkpointPlanBrokerUnitState(ctx, paths)') || (source.match(/checkpointPlanBrokerUnitState\(/g) ?? []).length !== 0) throw new Error('fixture state query must not reselect a unit through the production helper');
  const confirmWrapper = uniqueSourceRegion(source, 'func confirmPlanBrokerCPUUnitAbsent(paths checkpointPlanBrokerPaths, unit string) error {', 'func confirmPlanBrokerCPUUnitAbsentWithin(');
  requireText(confirmWrapper, ['return confirmPlanBrokerCPUUnitAbsentWithin(paths, unit, time.Now().Add(5*time.Second))'], 'single-deadline absence wrapper');
  const confirm = uniqueSourceRegion(source, 'func confirmPlanBrokerCPUUnitAbsentWithin(paths checkpointPlanBrokerPaths, unit string, deadline time.Time) error {', 'func planBrokerCPUUnitConfirmedAbsent(');
  const resetAt = confirm.indexOf('checkpointFixedSystemctl, "reset-failed", unit');
  const pollAt = confirm.indexOf('for {');
  const resetFenceAt = confirm.indexOf('if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before reset-failed") }');
  const rebindingAt = confirm.indexOf('if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before the absence query")');
  const showAt = confirm.indexOf('checkpointFixedSystemctl, "show", unit');
  if (!confirm.includes('context.WithDeadline(context.Background(), deadline)') || !confirm.includes('bytes.Equal(output, []byte("not-found\\n"))') || !confirm.includes('time.NewTimer(pause)') || !confirm.includes('pause := 25 * time.Millisecond') || pollAt < 0 || resetFenceAt < 0 || resetAt <= resetFenceAt || rebindingAt <= pollAt || showAt <= rebindingAt || !confirm.includes('remaining := time.Until(deadline)') || confirm.includes('context.WithTimeout(context.Background(), remaining)')) throw new Error('absence collector must repeatedly query under one absolute deadline with full binding before every query');

  const lifecycle = uniqueSourceRegion(source, 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {', 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {');
  const crash = uniqueSourceRegion(source, 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {', 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {');
  for (const [label, region, unitVar] of [['lifecycle', lifecycle, 'unitIdentity'], ['crash', crash, 'unitName']]) {
    const bindAt = region.indexOf(`${unitVar}, err := prebindPlanBrokerCPUFixtureUnit(paths, root, rootInfo)`);
    const cleanupAt = region.indexOf('cleanup := func() error {');
    const treeAt = region.indexOf('createPlanBrokerCPUFixtureTree(paths)');
    const postTree = `if checkpointPlanBrokerUnitName(paths) != ${unitVar} {`;
    const postAt = region.indexOf(postTree);
    if (bindAt < 0 || cleanupAt <= bindAt || treeAt <= cleanupAt || postAt <= treeAt) throw new Error(`${label} fixture must bind before cleanup/tree and recheck after the complete tree`);
    if (!region.includes('checkpointPlanBrokerPrivateFixturePathSet(paths)') || !region.includes('os.SameFile(rootInfo, currentRoot)') || !region.includes(`if planBrokerCPUFixtureUnitBound(paths, ${unitVar}) {`) || !region.includes(`confirmPlanBrokerCPUUnitAbsentWithin(paths, ${unitVar}, time.Now().Add(5*time.Second))`) || !region.includes(`else if !planBrokerCPUUnitConfirmedAbsent(${unitVar})`) || !region.includes('preserving private fixture')) throw new Error(`${label} cleanup can query/reset a fallback unit or delete under uncertain binding`);
    if (region.slice(0, treeAt).includes('checkpointPlanBrokerUnitName(paths)')) throw new Error(`${label} fixture uses the production fallback before its private tree exists`);
  }

  const start = uniqueSourceRegion(source, 'func startPlanBrokerCPUTransient(paths checkpointPlanBrokerPaths, workerSHA string) error {', 'func startPlanBrokerCPUBroker(');
  requireText(start, ['planBrokerCPUFixtureUnitBound(paths, paths.fixtureUnit)', '"--unit="+strings.TrimSuffix(paths.fixtureUnit, ".service")', '"--property=RuntimeMaxSec=90s"', '"--property=TimeoutStopSec=5s"', 'assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths, paths.fixtureUnit)'], 'transient unit startup');
  if (start.includes('checkpointPlanBrokerUnitName(')) throw new Error('transient start must use only the pre-bound private unit name');
  const deadline = uniqueSourceRegion(source, 'func assertPlanBrokerCPUUnitHasParentIndependentDeadline(paths checkpointPlanBrokerPaths, unit string) error {', 'func parsePlanBrokerCPUDurationMicros(');
  requireText(deadline, ['planBrokerCPUFixtureUnitBound(paths, unit)', 'context.WithTimeout(context.Background(), 5*time.Second)', 'checkpointFixedSystemctl, "show", unit', 'parsePlanBrokerCPUDeadlineOutput(raw)', 'runtimeMicros != 90000000 || stopMicros != 5000000'], 'unit deadline observation');
  const duration = uniqueSourceRegion(source, 'func parsePlanBrokerCPUDurationMicros(raw string) (uint64, error) {', 'func parsePlanBrokerCPUDeadlineOutput(');
  requireText(duration, ['maxMicros uint64 = 90000000', 'strings.TrimSpace(raw) != raw', 'value[0] == \'0\'', 'strconv.ParseUint(value, 10, 64)', 'strings.Split(raw, " ")', 'selected.rank >= previousRank', 'number > ^uint64(0)/selected.factor', 'total+part > maxMicros'], 'finite systemd duration parser');
  const envelope = uniqueSourceRegion(source, 'func parsePlanBrokerCPUDeadlineOutput(raw []byte) (uint64, uint64, error) {', 'func stopPlanBrokerCPUUnit(');
  requireText(envelope, ['raw[len(raw)-1] != \'\\n\'', 'len(raw) > checkpointUnitMaxOutput', 'strings.Cut(line, "=")', 'values[key]', 'len(values) != 2', 'runtimeMicros != 90000000 || stopMicros != 5000000'], 'exact deadline response envelope');
  const parserControls = uniqueSourceRegion(source, 'func verifyPlanBrokerCPUTestInventoryParserControls() error {', 'func readPlanBrokerCPUReceipt(');
  const positiveAt = parserControls.indexOf('parsePlanBrokerCPUDeadlineOutput(positiveOutput)');
  const negativeAt = parserControls.indexOf('for _, malformed := range []string{');
  if (positiveAt < 0 || negativeAt <= positiveAt || !parserControls.includes('{"1min 30s", 90000000}') || !parserControls.includes('{"5s", 5000000}') || !parserControls.includes('parsePlanBrokerCPUDurationMicros(malformed)')) throw new Error('duration parser controls must execute known positives before malformed and wrong-field negatives');
  return true;
}

function selfTestTransport12Source(source) {
  validateTransport12Source(source);
  const replaceExactlyOnce = (text, needle, replacement) => {
    if (text.split(needle).length !== 2) throw new Error('transport12 source mutant anchor is not exact-once');
    return text.replace(needle, replacement);
  };
  const reject = (mutant, label) => {
    let rejected = false;
    try { validateTransport12Source(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`transport12 source validator accepted ${label}`);
  };
  reject(replaceExactlyOnce(source, 'unitIdentity, err := prebindPlanBrokerCPUFixtureUnit(paths, root, rootInfo)', 'unitIdentity := checkpointPlanBrokerUnitName(paths)'), 'pre-tree fallback unit selection');
  reject(replaceExactlyOnce(source, 'unitName, err := prebindPlanBrokerCPUFixtureUnit(paths, root, rootInfo)', 'unitName := checkpointPlanBrokerUnitName(paths)'), 'crash-fixture pre-tree fallback unit selection');
  reject(replaceExactlyOnce(source, 'if checkpointPlanBrokerUnitName(paths) != unitIdentity {', 'if false {'), 'missing lifecycle post-tree binding');
  reject(replaceExactlyOnce(source, 'if checkpointPlanBrokerUnitName(paths) != unitName {', 'if false {'), 'missing crash post-tree binding');
  reject(replaceExactlyOnce(source, 'if planBrokerCPUFixtureUnitBound(paths, unitIdentity) {', 'if true {'), 'unfenced cleanup unit-state query');
  reject(replaceExactlyOnce(source, 'if planBrokerCPUFixtureUnitBound(paths, unitName) {', 'if true {'), 'unfenced crash cleanup unit-state query');
  reject(replaceExactlyOnce(source, 'if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before reset-failed") }', 'if false { return errors.New("fixture unit binding changed before reset-failed") }'), 'unfenced mutating absence query');
  reject(replaceExactlyOnce(source, 'if !planBrokerCPUFixtureUnitBound(paths, unit) { return errors.New("fixture unit binding changed before the absence query") }', 'if false { return errors.New("fixture unit binding changed before the absence query") }'), 'unfenced read-only absence confirmation after reset');
  const absence = uniqueSourceRegion(source, 'func confirmPlanBrokerCPUUnitAbsentWithin(paths checkpointPlanBrokerPaths, unit string, deadline time.Time) error {', 'func planBrokerCPUUnitConfirmedAbsent(');
  reject(replaceExactlyOnce(source, absence, absence.replace('for {\n\t\tif ctx.Err()', 'if ctx.Err()')), 'absence collector loses repeated LoadState polling');
  reject(replaceExactlyOnce(source, absence, absence.replace('context.WithDeadline(context.Background(), deadline)', 'context.WithTimeout(context.Background(), 5*time.Second)')), 'absence collector creates a fresh deadline');
  reject(replaceExactlyOnce(source, 'unit, err, _ := planBrokerCPUFixtureUnitStateObserved(ctx, paths)\n\treturn unit, err', 'unit, err, _ := planBrokerCPUFixtureUnitStateObserved(ctx, paths)\n\treturn checkpointPlanBrokerUnitState(ctx, paths)'), 'production helper forwarding after private precheck');
  reject(replaceExactlyOnce(source, 'if capturedUnit != paths.fixtureUnit || !planBrokerCPUFixtureUnitBound(paths, capturedUnit) {\n\t\treturn checkpointFixedUnitState{}, errors.New("private fixture binding changed during unit-state query"), "private_binding"', 'if false {\n\t\treturn checkpointFixedUnitState{}, errors.New("private fixture binding changed during unit-state query"), "private_binding"'), 'missing post-query private unit revalidation');
  reject(replaceExactlyOnce(source, 'runtimeMicros, stopMicros, err := parsePlanBrokerCPUDeadlineOutput(raw)\n\tif err != nil || runtimeMicros != 90000000 || stopMicros != 5000000 {', 'runtimeMicros, stopMicros, err := parsePlanBrokerCPUDeadlineOutput(raw)\n\tif err != nil {'), 'wrong duration acceptance');
  reject(replaceExactlyOnce(source, 'number > ^uint64(0)/selected.factor', 'false'), 'unchecked duration multiplication');
  return true;
}

function validateTransport14InactiveWaitSource(source) {
  const wrapper = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error) {', '\nfunc planBrokerCPUFixtureUnitStateObserved(');
  const expectedWrapper = 'func planBrokerCPUFixtureUnitState(ctx context.Context, paths checkpointPlanBrokerPaths) (checkpointFixedUnitState, error) {' +
    '\n\tunit, err, _ := planBrokerCPUFixtureUnitStateObserved(ctx, paths)' +
    '\n\treturn unit, err\n}\n';
  if (wrapper !== expectedWrapper) throw new Error('legacy state wrapper must retain the exact return behavior through one observed query');
  const observed = uniqueSourceRegion(source, 'func planBrokerCPUFixtureUnitStateObserved(', '\nfunc planBrokerCPUFixtureStoppedStateObserved(');
  for (const required of [
    'capturedUnit := paths.fixtureUnit',
    'if !planBrokerCPUFixtureUnitBound(paths, capturedUnit)',
    'checkpointPlanBrokerRun(ctx, checkpointFixedSystemctl, "show", capturedUnit',
    '"--property=MainPID"', '"--property=InvocationID"', '"--property=ControlGroup"', '"--property=ActiveState"', '"--property=SubState"',
    'len(raw) > checkpointUnitMaxOutput', "raw[len(raw)-1] != '\\n'", 'parseCheckpointPlanBrokerUnitState(raw)',
    'capturedUnit != paths.fixtureUnit', '!planBrokerCPUFixtureUnitBound(paths, capturedUnit)',
    '"private_binding"', '"show_unavailable"', '"show_envelope"', '"state_parse"',
    'if shapeCode := planBrokerCPUUnitStateParseShapeCode(raw); shapeCode != "state_parse" {', 'return checkpointFixedUnitState{}, err, shapeCode', 'return checkpointFixedUnitState{}, err, "state_parse"',
  ]) if (!observed.includes(required)) throw new Error(`observed private state source is missing ${required}`);
  if ((observed.match(/checkpointPlanBrokerRun\(/g) ?? []).length !== 1 || (observed.match(/parseCheckpointPlanBrokerUnitState\(/g) ?? []).length !== 1) throw new Error('observed private state must query and parse exactly once');
  const parseAt = observed.indexOf('unit, err := parseCheckpointPlanBrokerUnitState(raw)');
  const parserFailureAt = observed.indexOf('if err != nil {', parseAt);
  const optionalDiagnosticAt = observed.indexOf('if shapeCode := planBrokerCPUUnitStateParseShapeCode(raw); shapeCode != "state_parse" {', parserFailureAt);
  if (parseAt < 0 || parserFailureAt <= parseAt || optionalDiagnosticAt <= parserFailureAt ||
      observed.indexOf('return checkpointFixedUnitState{}, err, shapeCode', optionalDiagnosticAt) < optionalDiagnosticAt ||
      observed.indexOf('return checkpointFixedUnitState{}, err, "state_parse"', optionalDiagnosticAt) < optionalDiagnosticAt) throw new Error('finite state-shape diagnosis must occur only after unchanged strict-parser failure and never accept it');
  if ((observed.match(/planBrokerCPUUnitStateParseShapeCode\(raw\)/g) ?? []).length !== 1) throw new Error('private state shape must classify the captured response exactly once after strict parser failure');
  const shapeCode = uniqueSourceRegion(source, 'func planBrokerCPUUnitStateParseShapeCode(raw []byte) string {', '\nfunc createPlanBrokerCPUFixtureTree(');
  for (const required of [
    'len(raw) > checkpointUnitMaxOutput', "raw[len(raw)-1] != '\\n'", '!utf8.Valid(raw)',
    'strings.IndexFunc(line, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0', 'strings.TrimSuffix(string(raw), "\\n")',
    'len(values) != 5', 'key != "MainPID"', 'key != "InvocationID"', 'key != "ControlGroup"', 'key != "ActiveState"', 'key != "SubState"',
    'if _, exists := values[key]', 'values[key] == ""', 'invocationEmpty := values["InvocationID"] == ""',
    'controlGroupEmpty := values["ControlGroup"] == ""', 'strconv.Atoi(values["MainPID"])',
    'pid == 0 && values["ActiveState"] != "inactive" && values["ActiveState"] != "failed"',
    'pid > 1 && values["ActiveState"] != "active"', 'invocationEmpty || controlGroupEmpty',
    'return "empty_invocation"', 'return "empty_control_group"', 'return "empty_invocation_control_group"', 'return "pid_state_shape"', 'return "state_parse"',
  ]) if (!shapeCode.includes(required)) throw new Error(`finite state-shape classifier is missing ${required}`);
  if ((shapeCode.match(/return "(?:empty_invocation|empty_control_group|empty_invocation_control_group|pid_state_shape)"/g) ?? []).length !== 4 ||
      shapeCode.includes('checkpointPlanBrokerRun(') || shapeCode.includes('fmt.') || shapeCode.includes('+ string(raw)') || shapeCode.includes('errors.New(string(raw))')) throw new Error('state-shape classifier must expose only four finite codes and perform no external effect or raw output');
  const parserControls = uniqueSourceRegion(source, 'func verifyPlanBrokerCPUTestInventoryParserControls() error {', '\nfunc readPlanBrokerCPUReceipt(');
  const positiveControlAt = parserControls.indexOf('planBrokerCPUUnitStateParseShapeCode(positive.raw)');
  const strictParserAt = parserControls.indexOf('parseCheckpointPlanBrokerUnitState(positive.raw)');
  const malformedControlsAt = parserControls.indexOf('for _, malformed := range [][]byte{', strictParserAt);
  for (const code of ['empty_invocation', 'empty_control_group', 'empty_invocation_control_group', 'pid_state_shape']) {
    if (!parserControls.includes(`"${code}"`)) throw new Error(`actual Go parser controls are missing ${code} positive`);
  }
  if (positiveControlAt < 0 || strictParserAt <= positiveControlAt || malformedControlsAt <= strictParserAt ||
      !parserControls.includes('planBrokerCPUUnitStateParseShapeCode(malformed) != "state_parse"') || !parserControls.includes('PrivatePath=/secret') ||
      !parserControls.includes('SubState=\\n') || !parserControls.includes('MainPID=invalid') ||
      !parserControls.includes('SubState=dead\\xff') || !parserControls.includes('ControlGroup=\\r\\n')) throw new Error('complete state-shape diagnostics require positive-before-malformed, mixed-fault, invalid-PID, text-envelope and private-field controls');
  const parserControlCall = 'if err := verifyPlanBrokerCPUTestInventoryParserControls(); err != nil {';
  if ((source.match(/if err := verifyPlanBrokerCPUTestInventoryParserControls\(\); err != nil \{/g) ?? []).length !== 2 ||
      !source.includes('func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {\n\tif os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn || os.Geteuid() != 0 {\n\t\tt.Fatal("CPU lifecycle fixture requires its explicit local root opt-in")\n\t}\n\t' + parserControlCall) ||
      !source.includes('func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {\n\tif os.Getenv(planBrokerCPUEnv) != planBrokerCPUOptIn || os.Geteuid() != 0 {\n\t\tt.Fatal("CPU start-request crash fixture requires its explicit local root opt-in")\n\t}\n\t' + parserControlCall)) throw new Error('state-shape controls must remain inside both existing inventoried owner tests');
  const inactive = uniqueSourceRegion(source, 'func waitPlanBrokerCPUInactive(paths checkpointPlanBrokerPaths, priorInvocation string) error {', '\nfunc waitPlanBrokerCPUSocket(');
  const wrapperCall = '_, err := waitPlanBrokerCPUInactiveObserved(paths, priorInvocation)\n\treturn err';
  const successGuard = 'if err == nil && unit.MainPID == 0 && (unit.Invocation == "" && unit.ControlGroup == "" || unit.Invocation == strings.ToLower(priorInvocation) && unit.ControlGroup != "") {';
  for (const required of [
    wrapperCall, 'func waitPlanBrokerCPUInactiveObserved(', 'lastCode := "unavailable"', 'time.Now().Add(10 * time.Second)', 'for time.Now().Before(deadline) {',
    'planBrokerCPUFixtureStoppedStateObserved(context.Background(), paths)', successGuard,
    'unit.Load == "loaded"', '(unit.Sub == "dead" || unit.Sub == "exited")', 'time.Sleep(100 * time.Millisecond)',
    'errors.New("exact transient unit did not become freshly inactive with an empty cgroup")',
    'lastCode = "nonzero_pid"', 'lastCode = "invocation_mismatch"',
  ]) if (!inactive.includes(required)) throw new Error(`inactive wait source is missing ${required}`);
  const inactiveLoop = uniqueSourceRegion(source, 'func waitPlanBrokerCPUInactiveObserved(paths checkpointPlanBrokerPaths, priorInvocation string) (string, error) {', '\nfunc waitPlanBrokerCPUSocket(');
  if (!inactiveLoop.includes('deadline := time.Now().Add(10 * time.Second)') || !inactiveLoop.includes('for time.Now().Before(deadline) {')) throw new Error('inactive wait lacks its fixed bounded deadline');
  if ((inactiveLoop.match(/planBrokerCPUFixtureStoppedStateObserved\(context.Background\(\), paths\)/g) ?? []).length !== 1 ||
      (inactiveLoop.match(/time\.Sleep\(100 \* time\.Millisecond\)/g) ?? []).length !== 1) throw new Error('inactive wait query/sleep count changed');
  if (inactive.indexOf(successGuard) < 0 || inactive.indexOf('unit.Load == "loaded"') < inactive.indexOf(successGuard)) throw new Error('inactive typed-state checks no longer follow the exact empty-pair predicate');
  const stoppedProof = uniqueSourceRegion(source, 'func waitPlanBrokerCPUStoppedProof(paths checkpointPlanBrokerPaths, held planBrokerCPULaunchIdentity, pidfd int) (string, error) {', '\nfunc waitPlanBrokerCPUStoppedCleanupProof(');
  for (const required of ['planBrokerCPUFixtureStoppedStateObserved(ctx, paths)', 'verifyCheckpointPlanBrokerStoppedObservation(observed, paths, prior)', 'verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, deadline)', 'checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)', 'time.Now().Add(10 * time.Second)', 'time.Now().Before(deadline)', 'context.WithDeadline(context.Background(), deadline)']) if (!stoppedProof.includes(required)) throw new Error(`pre-ack terminal proof is missing ${required}`);
  const pidfdTerminal = uniqueSourceRegion(source, 'func verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd int, held planBrokerCPULaunchIdentity, deadline time.Time) error {', '\nfunc planBrokerCPUPIDFDTarget(');
  if (!pidfdTerminal.includes('planBrokerCPUTerminalPollEventsValid(descriptor[0].Revents)') || !pidfdTerminal.includes('errors.Is(procErr, os.ErrNotExist)') || !pidfdTerminal.includes('deadline')) throw new Error('terminal PIDFD proof accepts ambiguous readiness or a still-present PID');
  const marker = uniqueSourceRegion(source, 'func planBrokerCPUInactiveWaitMarker(', '\nfunc planBrokerCPUWorkerEmptyDiagnosticCode(');
  const workerCodes = uniqueSourceRegion(source, 'func planBrokerCPUWorkerEmptyDiagnosticCode(', '\nfunc waitPlanBrokerCPUInactiveObserved(');
  for (const code of ['private_binding', 'show_unavailable', 'show_envelope', 'state_parse', 'empty_invocation', 'empty_control_group', 'empty_invocation_control_group', 'pid_state_shape', 'unit_definition_missing', 'nonzero_pid', 'invocation_mismatch', 'worker_state', 'jobs_unavailable', 'jobs_malformed', 'pending_job', 'cgroup_unconfirmed', 'unavailable']) {
    if (!marker.includes(`"${code}"`)) throw new Error(`inactive wait code allowlist is missing ${code}`);
  }
  if (!marker.includes('owner != "TestCheckpointPlanRelaunchCPULifecycleSequence" && owner != "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect"') ||
      !marker.includes('return "__PLAN_RELAUNCH_INACTIVE_WAIT__:" + owner + ":" + code') || marker.includes('err.Error()')) throw new Error('inactive wait marker must bind fixed owners and contain only fixed enum data');
  for (const [message, code] of [
    ['fixed worker is not freshly inactive', 'worker_state'],
    ['systemd pending-job state is unavailable', 'jobs_unavailable'],
    ['systemd pending-job state is malformed', 'jobs_malformed'],
    ['fixed worker has a pending systemd job', 'pending_job'],
    ['fixed worker control group is not confirmed empty', 'cgroup_unconfirmed'],
  ]) if (!workerCodes.includes(`case "${message}":\n\t\treturn "${code}"`)) throw new Error(`worker-empty fixed error mapping is missing ${code}`);
  if (!workerCodes.includes('default:\n\t\treturn "unavailable"') || (workerCodes.match(/err\.Error\(\)/g) ?? []).length !== 1) throw new Error('worker-empty diagnostic must map only fixed known errors and fail closed');

  const ownerSites = [
    ['TestCheckpointPlanRelaunchCPULifecycleSequence', 'unitIdentity'],
    ['TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect', 'unitName'],
  ];
  for (const [owner, unitVar] of ownerSites) {
    const startNeedle = `func ${owner}(t *testing.T) {`;
    const nextNeedle = owner === ownerSites[0][0] ? 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {' : 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {';
    const startAt = source.indexOf(startNeedle), endAt = source.indexOf(nextNeedle, startAt + startNeedle.length);
    if (startAt < 0 || endAt <= startAt || source.indexOf(startNeedle, startAt + startNeedle.length) >= 0) throw new Error(`${owner} source region is missing or ambiguous`);
    const region = source.slice(startAt, endAt);
    const observedCall = 'waitCode, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)';
    const markerCall = `fmt.Fprintln(os.Stderr, planBrokerCPUInactiveWaitMarker("${owner}", waitCode))`;
    const stdoutMarkerCall = markerCall.replace('os.Stderr', 'os.Stdout');
    const expectedFailure = owner === ownerSites[0][0]
      ? 't.Fatalf("holder retention/lifetime oracle: confirm the first worker remains an exact loaded stopped unit with empty cgroup: %v", err)'
      : 't.Fatal("confirm the first worker is stopped and its cgroup empty")';
    const expectedBlock = owner === ownerSites[0][0]
      ? 'if err != nil {\n\t\tif holder.releaseDone {\n\t\t\tif waitCode != "unit_definition_missing" {\n\t\t\t\tt.Fatalf("early-release proof was inconclusive (%s), not the intended missing-definition predicate: %v", waitCode, err)\n\t\t\t}\n\t\t\tfmt.Println(planBrokerCPUHolderEarlyReleasePredicate)\n\t\t} else {\n\t\t\t' + stdoutMarkerCall + '\n\t\t}\n\t\t' + expectedFailure + '\n\t}'
      : 'if err != nil {\n\t\t' + stdoutMarkerCall + '\n\t\t' + expectedFailure + '\n\t}';
    if ((region.match(/waitCode, err := waitPlanBrokerCPUStoppedProof\(/g) ?? []).length !== 1 || !region.includes(observedCall) || !region.includes(stdoutMarkerCall) ||
        !region.includes(expectedBlock)) throw new Error(`${owner} must consume exactly one first-stop result through its fixed failure-only marker`);
    const diagnosticAt = region.indexOf(observedCall), receiptAt = region.indexOf('makePlanBrokerCPUStopAck(', diagnosticAt);
    const diagnosticBlock = region.slice(diagnosticAt, receiptAt);
    const holdAt = region.indexOf('victimPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(victimLaunch)');
    const stopAt = region.indexOf(`if err := stopPlanBrokerCPUUnit(${unitVar});`, holdAt);
    if (holdAt < 0 || stopAt <= holdAt || stopAt > region.indexOf(observedCall) || region.indexOf(observedCall) > region.indexOf('makePlanBrokerCPUStopAck(') ||
        diagnosticAt < 0 || receiptAt <= diagnosticAt || diagnosticBlock.includes('fmt.Errorf') || diagnosticBlock.includes('err.Error()') ||
        diagnosticBlock.includes('t.Fatalf("confirm the first worker')) throw new Error(`${owner} changed first-stop order or leaks raw diagnostic data`);
  }
  return true;
}

function selfTestTransport14InactiveWaitSource(source) {
  validateTransport14InactiveWaitSource(source);
  const once = (text, before, after) => {
    if (text.split(before).length !== 2) throw new Error('transport20 source mutant anchor is not exact-once');
    return text.replace(before, after);
  };
  const stopped = uniqueSourceRegion(source, 'func waitPlanBrokerCPUStoppedProof(', '\nfunc waitPlanBrokerCPUStoppedCleanupProof(');
  const reject = (region, mutant, label, category) => {
    let reason = '';
    try { validateTransport14InactiveWaitSource(source.replace(region, mutant)); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason || (category && !reason.includes(category))) throw new Error(`transport20 owner diagnostic source control accepted ${label}: ${reason || 'accepted'}`);
  };
  reject(stopped, once(stopped, 'observed, err, stateCode := planBrokerCPUFixtureStoppedStateObserved(ctx, paths)', 'observed, err, stateCode := planBrokerCPUFixtureStoppedStateObserved(context.Background(), paths)'), 'lost shared bounded context', 'pre-ack terminal proof');
  reject(stopped, once(stopped, 'for time.Now().Before(deadline) {', 'for true {'), 'removed stopped proof deadline', 'pre-ack terminal proof');
  reject(stopped, once(stopped, 'verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, deadline)', 'nil'), 'removed held pidfd terminal observation', 'pre-ack terminal proof');
  reject(stopped, once(stopped, 'checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)', 'nil'), 'removed exact jobs and old-cgroup proof', 'pre-ack terminal proof');
  const lifecycleStart = source.indexOf('func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {');
  const lifecycleEnd = source.indexOf('\nfunc TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {', lifecycleStart + 1);
  if (lifecycleStart < 0 || lifecycleEnd <= lifecycleStart) throw new Error('lifecycle owner source region is missing or ambiguous');
  const lifecycle = source.slice(lifecycleStart, lifecycleEnd);
  reject(lifecycle, once(lifecycle, 'waitCode, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)', 'waitCode, err := "", nil'), 'disconnected lifecycle owner from the proof result', 'must consume exactly one first-stop result');
  const crashStart = source.indexOf('func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {');
  const crashEnd = source.indexOf('\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {', crashStart + 1);
  if (crashStart < 0 || crashEnd <= crashStart) throw new Error('crash owner source region is missing or ambiguous');
  const crash = source.slice(crashStart, crashEnd);
  reject(crash, once(crash, 'waitCode, err := waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)', 'waitCode, err := "", nil'), 'disconnected crash owner from the proof result', 'must consume exactly one first-stop result');
  const shape = uniqueSourceRegion(source, 'func planBrokerCPUUnitStateParseShapeCode(raw []byte) string {', '\nfunc createPlanBrokerCPUFixtureTree(');
  reject(shape, once(shape, 'func planBrokerCPUUnitStateParseShapeCode(raw []byte) string {', 'func planBrokerCPUUnitStateParseShapeCode(raw []byte) string {\n\t_, _ = checkpointPlanBrokerRun(context.Background(), checkpointFixedSystemctl, "show", "unexpected")'), 'diagnostic classifier gained a second query', 'no external effect');
  return true;
}

function validateStoppedStateProofSource(broker, brokerTest, cpuFixture) {
  const ordinaryImports = brokerTest.match(/import\s*\(([\s\S]*?)\n\)/)?.[1] ?? '';
  if (!/^\s*"vram-governor\/internal\/wsproto"\s*$/m.test(ordinaryImports)) throw new Error('ordinary Linux broker tests are missing the wsproto package import');
  if (!/^\s*"fmt"\s*$/m.test(ordinaryImports)) throw new Error('ordinary Linux broker tests are missing the fmt package import');
  if (!brokerTest.startsWith('//go:build linux\n') || /planBrokerCPULaunchIdentity|verifyPlanBrokerCPUStopReceiptBinding/.test(brokerTest)) throw new Error('ordinary Linux broker tests reference a checkpoint_plan_broker_cpu-only declaration');
  if (!cpuFixture.startsWith('//go:build linux && checkpoint_plan_broker_cpu\n')) throw new Error('CPU owner fixture lost its exact opt-in build constraint');
  const strictParser = uniqueSourceRegion(broker, 'func parseCheckpointPlanBrokerUnitState(raw []byte) (checkpointFixedUnitState, error) {', 'func checkpointPlanBrokerWorkerEmpty(');
  if (Buffer.byteLength(strictParser, 'utf8') !== 1481 || createHash('sha256').update(strictParser).digest('hex') !== '313164684f0d984ce720dca2e7222db47fca87fd5aef11c1c0da2d84937b7e51') throw new Error('strict active-unit parser changed from the authenticated Transport17 baseline');
  const parser = uniqueSourceRegion(broker, 'func parseCheckpointPlanBrokerStoppedState(raw []byte) (checkpointPlanBrokerStoppedState, error) {', '\nfunc verifyCheckpointPlanBrokerStoppedObservation(');
  for (const token of ['parseCheckpointPlanBrokerStoppedObservation(raw)', 'observed.Load != "loaded"']) if (!parser.includes(token)) throw new Error('strict loaded-state stopped parser does not preserve its six-field observation');
  const observation = uniqueSourceRegion(broker, 'func parseCheckpointPlanBrokerStoppedObservation(raw []byte) (checkpointPlanBrokerStoppedState, error) {', '\nfunc verifyCheckpointPlanBrokerStoppedObservation(');
  for (const token of ['!utf8.Valid(raw)', 'key != "MainPID"', 'key != "InvocationID"', 'key != "ControlGroup"', 'key != "ActiveState"', 'key != "SubState"', 'key != "LoadState"', 'len(values) != 6', 'values["MainPID"] != "0"', 'values["ActiveState"] != "inactive"', 'values["LoadState"] != "loaded" && values["LoadState"] != "not-found"', 'values["SubState"] != "dead" && values["SubState"] != "exited"', 'if _, exists := values[key]']) if (!observation.includes(token)) throw new Error('bounded six-field stopped observation lost a required exact-state guard');
  const stopped = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStoppedObservation(', '\nfunc checkpointPlanBrokerOriginalWorkerTerminalResult(');
  for (const token of ['invocationEmpty != groupEmpty', 'observed.Invocation != strings.ToLower(prior.InvocationID)', 'observed.ControlGroup != prior.ControlGroup', 'prior.ControlGroup != filepath.Join("/system.slice", unit)', '!prior.ReleaseTerminal']) if (!stopped.includes(token)) throw new Error('stopped state no longer requires the signed prior identity pair');
  const terminal = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerOriginalWorkerTerminal(', '\nfunc checkpointPlanBrokerOriginalWorkerTerminalResult(');
  const terminalResult = uniqueSourceRegion(broker, 'func checkpointPlanBrokerOriginalWorkerTerminalResult(', '\nfunc checkpointPlanBrokerStoppedWorkerEmpty(');
  if (!terminal.includes('checkpointProcessStart(') || !terminal.includes('checkpointPlanBrokerOriginalWorkerTerminalResult(prior, err)') || !terminalResult.includes('errors.Is(procErr, os.ErrNotExist)') || !terminalResult.includes('original worker incarnation remains present or its terminal state is uncertain')) throw new Error('original PID/start terminal proof is not fail-closed');
  const empty = uniqueSourceRegion(broker, 'func checkpointPlanBrokerStoppedWorkerEmpty(', '\nfunc parseCheckpointPlanBrokerUnitState(');
  for (const token of ['queryCheckpointPlanBrokerStoppedState(ctx, paths)', 'checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(prior.WorkerPID)), prior.WorkerPID)', '"list-jobs"', 'checkpointPlanBrokerPendingJobForUnit(jobs, checkpointPlanBrokerUnitName(paths))', 'filepath.Clean(prior.ControlGroup)', 'readCheckpointPlanBrokerCgroupProcs(group)', 'verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths, observed, prior, procErr, jobs, jobsErr, body, err, false)']) if (!empty.includes(token)) throw new Error('fresh no-job/old-cgroup proof is incomplete');
  const proofSample = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStoppedWorkerEmptySample(', '\nfunc parseCheckpointPlanBrokerUnitState(');
  for (const token of ['verifyCheckpointPlanBrokerStoppedCleanupObservation(observed, paths, prior)', 'verifyCheckpointPlanBrokerStoppedObservation(observed, paths, prior)', 'checkpointPlanBrokerOriginalWorkerTerminalResult(prior, procErr)', 'jobsErr != nil', 'if err != nil {', 'if pending {', 'systemd pending-job state is malformed', 'fixed worker has a pending systemd job', 'fixed worker control group is not confirmed empty', 'len(bytes.TrimSpace(cgroupProcs)) != 0']) if (!proofSample.includes(token)) throw new Error('shared stop/cleanup proof omits a real terminal, exact-job or old-cgroup rejection predicate');
  const cleanupObservation = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStoppedCleanupObservation(', '\nfunc verifyCheckpointPlanBrokerStoppedObservationLoad(');
  if (!cleanupObservation.includes('verifyCheckpointPlanBrokerStoppedObservationLoad(observed, paths, prior, false)')) throw new Error('cleanup-only absent-definition proof is not separated from loaded authority');
  const cleanupProof = uniqueSourceRegion(cpuFixture, 'func waitPlanBrokerCPUStoppedCleanupProof(', '\nfunc waitPlanBrokerCPUInactiveObserved(');
  for (const token of ['planBrokerCPUFixtureStoppedStateRaw(ctx, paths)', 'parseCheckpointPlanBrokerStoppedObservation(raw)', 'planBrokerCPUStoppedStateParseShapeCode(raw, held.UnitName) != "unit_definition_missing"', 'verifyCheckpointPlanBrokerStoppedCleanupObservation(observed, paths, prior)', 'verifyPlanBrokerCPUTerminalPIDFDUntil(pidfd, held, deadline)', 'checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(held.PID)), held.PID)', '"list-jobs"', 'readCheckpointPlanBrokerCgroupProcs(group)', 'verifyCheckpointPlanBrokerStoppedWorkerEmptySample(paths, observed, prior, procErr, jobs, jobsErr, cgroupProcs, cgroupErr, true)']) if (!cleanupProof.includes(token)) throw new Error('cleanup lacks held terminal, actual loaded/not-found, exact jobs and old-cgroup proof');
  const prior = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerPriorStopResult(', '\nfunc checkpointPlanBrokerColdPriorStopReceipt(');
  for (const token of ['operation.Fence != fence', 'operation.Steps[priorStep]', 'state.Results[priorID]', 'result.NodeID != command.NodeID', 'result.Result["original_envelope"]', 'result.Result["pinned_root_public_key"]', 'bytes.Equal(resultPublic, pinnedPublic)', 'resultDigest != sha256Hex(receiptRaw)', 'wsproto.VerifyCommand(original', 'wsproto.CanonicalCommandEnvelope(original)', 'wsproto.ValidateOwnedStopCommandArgs', 'verifyOwnedStopReceipt(receiptRaw, pinnedPublic, originalWire, secret)']) if (!prior.includes(token)) throw new Error('prior command/key/receipt/fence authority join is incomplete');
  const cold = uniqueSourceRegion(broker, 'func checkpointPlanBrokerColdPriorStopReceipt(', '\nfunc validateCheckpointPlanRelaunchNodeIntent(');
  for (const token of ['readPublicKey: readPinnedRootStopPublicKeyAt', 'lstat:         os.Lstat', 'pathChain:     checkpointOwnedStopPathChainAt', 'readReceipt:   readPlanBrokerFile', 'checkpointProcessStart(filepath.Join("/proc", strconv.Itoa(pid)), pid)', 'checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, state, command, cfg.CommandSigningSecret, fixedIO)']) if (!cold.includes(token)) throw new Error('cold wrapper no longer supplies fixed real key/path/file/process readers');
  const coldReader = uniqueSourceRegion(broker, 'func checkpointPlanBrokerColdPriorStopReceiptWithIO(', '\n// verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence');
  for (const token of ['io.readPublicKey(stopPaths.PublicKey, stopPaths)', 'bytes.Equal(public, stopStep.PinnedRootStopPublicKey)', 'io.lstat(stopPaths.ReceiptDir)', 'io.pathChain(path, stopPaths, true)', 'io.readReceipt(path, 16<<10, 0o640)', 'stat.Uid != 0', 'stat.Gid != stopPaths.NodeGID', 'stat.Nlink != 1', 'int64(len(raw)) != info.Size()', 'sha256Hex(raw) != fmt.Sprint(command.Args["prior_receipt_sha256"])', 'io.processStart(terminalReceipt.WorkerPID)', 'verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(state, paths, command, operation, stopStep, raw, public, secret, procErr)']) if (!coldReader.includes(token)) throw new Error('cold owned-IO reducer omits a bounded key, path, owner, inode, currentness or process decision');
  const coldReducer = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence(', '\nfunc validateCheckpointPlanRelaunchNodeIntent(');
  for (const token of ['verifyCheckpointPlanBrokerPriorStopResult(state, paths, command, operation, stopStep, raw, public, secret)', 'checkpointPlanBrokerOriginalWorkerTerminalResult(receipt, procErr)']) if (!coldReducer.includes(token)) throw new Error('cold Go reducer omits signed predecessor validation or original-process terminal proof');
  const goInactiveMarker = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUInactiveWaitMarker(', '\nfunc closePlanBrokerCPUOpenedPIDFD(');
  if (!goInactiveMarker.includes('case "private_binding", "show_unavailable", "show_envelope", "state_parse", "empty_invocation", "empty_control_group", "empty_invocation_control_group", "pid_state_shape", "unit_definition_missing",')) throw new Error('Go inactive wait marker does not preserve the exact unit-definition diagnostic enum');
  const validate = uniqueSourceRegion(broker, 'func validateCheckpointPlanRelaunchNodeIntent(', '\nfunc reconcileCheckpointPlanBrokerQuery(');
  if (!validate.includes('verifyCheckpointPlanBrokerPriorStopResult(envelope.State, paths, command, stopOp, stopStep, priorWire') || !validate.includes('queryCheckpointPlanBrokerStoppedState(ctx, paths)')) throw new Error('initial admission is not joined to signed stop authority and typed stopped fields');
  const publish = uniqueSourceRegion(broker, 'func publishCheckpointPlanBrokerPlan(', '\nfunc awaitCheckpointPlanBrokerBinding(');
  if (publish.indexOf('checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)') < 0 || publish.indexOf('checkpointPlanBrokerWriteAtomic(path, next') <= publish.indexOf('checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)')) throw new Error('fresh stopped proof does not precede plan CAS');
  const start = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStartState(', '\nfunc mustPlanBrokerPublicKey(');
  if (!start.includes('checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)')) throw new Error('fresh stopped proof does not precede first start');
  const recovery = uniqueSourceRegion(broker, 'func reconcileCheckpointPlanBrokerPending(', '\nfunc ');
  for (const token of ['checkpointPlanBrokerColdPriorStopReceipt(paths, state, original, cfg)', 'queryCheckpointPlanBrokerStoppedState(ctx, paths)', 'checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, priorReceipt)', 'checkpointPlanRelaunchMayIssueFirstStart(stepID, entry.Stage)', 'checkpointPlanRelaunchMayJoinStartedProcess(stepID, entry.Stage)']) if (!recovery.includes(token)) throw new Error('cold recovery lost a receipt join, fresh stopped proof, or stage guard');

  const parserTest = uniqueSourceRegion(brokerTest, 'func TestPlanBrokerUnitParserRequiresCompleteFixedProperties(t *testing.T) {', '\nfunc TestPlanBrokerJobParserUsesExactUnitIdentity(');
  const unitControlGroup = parserTest.indexOf('unitControlGroup := filepath.Join');
  const activePositive = parserTest.indexOf('activeUnit, err := parseCheckpointPlanBrokerUnitState(active)');
  const activeAssert = parserTest.indexOf('activeUnit.MainPID != 42', activePositive);
  const activeNegative = parserTest.indexOf('inconsistentActive := []byte(strings.Replace(string(active), "ActiveState=active", "ActiveState=inactive", 1))', activeAssert);
  const activeReject = parserTest.indexOf('if _, err := parseCheckpointPlanBrokerUnitState(inconsistentActive); err == nil {', activeNegative);
  const pos = parserTest.indexOf('parseCheckpointPlanBrokerStoppedState(stopped)');
  const bound = parserTest.indexOf('verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, stopped)', pos);
  const blank = parserTest.indexOf('verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, blankPrior)', bound);
  const wrongPrior = parserTest.indexOf('wrongPrior := prior', blank);
  const wrongPriorControl = parserTest.indexOf('verifyCheckpointPlanBrokerStoppedObservation(mustParsePlanBrokerStoppedState(t, stopped), checkpointPlanBrokerPaths{}, wrongPrior)', wrongPrior);
  const neg = parserTest.indexOf('stoppedMutants := [][]byte{', blank);
  if (unitControlGroup < 0 || !parserTest.includes('unitControlGroup := filepath.Join("/system.slice", checkpointPlanBrokerUnitName(checkpointPlanBrokerPaths{}))') ||
      activePositive <= unitControlGroup || activeAssert <= activePositive || !parserTest.includes('activeUnit.Active != "active"') || !parserTest.includes('activeUnit.ControlGroup != unitControlGroup') || activeNegative <= activeAssert || activeReject <= activeNegative ||
      pos < 0 || bound <= pos || blank <= bound || wrongPrior <= blank || wrongPriorControl <= wrongPrior || neg <= wrongPriorControl ||
      (parserTest.match(/ControlGroup=%s/g) ?? []).length !== 3 || !parserTest.includes('ControlGroup: unitControlGroup') || !parserTest.includes('wrongPrior.ControlGroup = filepath.Join("/system.slice", "other.service")') ||
      !parserTest.includes('strings.Replace(string(stopped), "ControlGroup="+unitControlGroup') || !parserTest.includes('strings.Replace(string(blankPrior), "ControlGroup=\\n", "ControlGroup="+unitControlGroup+"\\n", 1)') || parserTest.includes('vram-governor-llama-server.service') ||
      !parserTest.includes('MainPID=42') || !parserTest.includes('ActiveState=active') || !parserTest.includes('MainPID=0') ||
      !parserTest.includes('LoadState=not-found') || !parserTest.includes('SubState=failed') || !parserTest.includes('other.service')) throw new Error('actual Go stopped parser controls lack derived exact-unit identity, active/inactive consistency, and positive-before-negative signed-prior coverage');
  const missingShape = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUStoppedStateParseShapeCode(', '\nfunc planBrokerCPUUnitStateParseShapeCode(');
  for (const token of ['parseCheckpointPlanBrokerStoppedObservation(raw)', 'observed.Load != "not-found"', 'invocationEmpty != groupEmpty', 'hex.DecodeString(observed.Invocation)', 'observed.ControlGroup != filepath.Join("/system.slice", unit)', 'return "unit_definition_missing"', 'return "state_parse"']) if (!missingShape.includes(token)) throw new Error('finite same-sample missing-definition diagnosis is not exact and fail-closed');
  const missingControls = uniqueSourceRegion(cpuFixture, 'func verifyPlanBrokerCPUTestInventoryParserControls() error {', '\nfunc verifyPlanBrokerCPUStoppedSampleControls() error {');
  for (const token of ['parseCheckpointPlanBrokerStoppedState(notFound)', 'planBrokerCPUStoppedStateParseShapeCode(notFound,', '"unit_definition_missing"', 'LoadState=loaded', 'MainPID=2', 'PrivatePath=/secret']) if (!missingControls.includes(token)) throw new Error('exact not-found diagnostic lacks strict-parser failure and mixed/hostile negatives');
  const markerPositiveAt = missingControls.indexOf('notFoundDiagnostic := []byte(');
  const markerOwnersAt = missingControls.indexOf('for _, owner := range []string{"TestCheckpointPlanRelaunchCPULifecycleSequence", "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect"}', markerPositiveAt);
  const invalidOwnerAt = missingControls.indexOf('planBrokerCPUInactiveWaitMarker("unexpected-owner"', markerOwnersAt);
  if (markerPositiveAt < 0 || markerOwnersAt <= markerPositiveAt || invalidOwnerAt <= markerOwnersAt || !missingControls.includes('planBrokerCPUInactiveWaitMarker(owner, missingCode)')) throw new Error('actual not-found marker positives for both owning tests must precede invalid/hostile marker negatives');

  const fixtureState = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUFixtureStoppedStateObserved(', '\nfunc planBrokerCPUUnitStateParseShapeCode(');
  for (const token of ['planBrokerCPUFixtureUnitBound(paths, capturedUnit)', '"--property=LoadState"', 'parseCheckpointPlanBrokerStoppedState(raw)', 'capturedUnit != paths.fixtureUnit']) if (!fixtureState.includes(token)) throw new Error('CPU fixture does not query its exact typed stopped unit');
  const hold = uniqueSourceRegion(cpuFixture, 'func holdPlanBrokerCPUTerminalPIDFD(', '\nfunc verifyPlanBrokerCPUTerminalPIDFD(');
  for (const token of ['unix.PidfdOpen(held.PID, 0)', 'planBrokerCPUPIDFDTarget(pidfd)', 'currentStart != held.StartTicks', 'unix.POLLIN', 'unix.PidfdSendSignal(pidfd, 0, nil, 0)']) if (!hold.includes(token)) throw new Error('CPU fixture does not hold the exact live worker PIDFD before stopping');
  const terminalMask = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUTerminalPollEventsValid(', '\nfunc runPlanBrokerCPUParentDeathHelper(');
  for (const token of ['revents&int16(unix.POLLIN) == 0', 'revents&int16(unix.POLLERR|unix.POLLNVAL) != 0', 'revents & ^allowed != 0', 'planBrokerCPUPollRDNORM', 'allowed := int16(unix.POLLIN|unix.POLLHUP)']) if (!terminalMask.includes(token)) throw new Error('CPU fixture terminal event mask is not a bounded documented readiness predicate');
  const terminalPIDFD = uniqueSourceRegion(cpuFixture, 'func verifyPlanBrokerCPUTerminalPIDFDUntil(', '\nfunc planBrokerCPUPIDFDTarget(');
  for (const token of ['planBrokerCPUTerminalPollEventsValid(descriptor[0].Revents)', 'errors.Is(procErr, os.ErrNotExist)', 'deadline']) if (!terminalPIDFD.includes(token)) throw new Error('CPU fixture PIDFD terminal proof is ambiguous or unbounded');
  const ack = uniqueSourceRegion(cpuFixture, 'func makePlanBrokerCPUStopAck(', '\nfunc writePlanBrokerCPUStopAck(');
  for (const token of ['verifyPlanBrokerCPUTerminalPIDFD(pidfd, held)', 'checkpointPlanBrokerStoppedWorkerEmpty(context.Background(), paths, candidate)', 'receipt.WorkerPID = held.PID', 'receipt.WorkerStartTicks = held.StartTicks', 'held.PlanSHA256', 'held.CurrentIncarnation', 'held.CustodyBindingSHA256', 'held.Alias']) if (!ack.includes(token)) throw new Error('synthetic stop ACK can be made without terminal proof and captured managed binding');
  const capture = uniqueSourceRegion(cpuFixture, 'func capturePlanBrokerCPULaunch(', '\nfunc planBrokerCPULaunchStillCurrent(');
  if (!capture.includes('binding.PlanSHA256 != sha256Hex(mustJSON(plan))') || !capture.includes('PlanSHA256: binding.PlanSHA256')) throw new Error('held managed-plan digest is not compared at capture and retained from the observed binding');
  const priorControls = uniqueSourceRegion(brokerTest, 'func testPlanBrokerPriorStopResultControls(t *testing.T) {', '\nfunc priorStopResult(');
  for (const token of ['OwnedStopOperations: map[string]ownedStopOperationState{"gpu-0": persistedOperation}', 'known exact durable prior stop proof', 'known exact cold prior-stop proof', 'for _, phase := range []string', 'missingOperationState.OwnedStopOperations = map[string]ownedStopOperationState{}', 'cold recovery lost the exact prior stop operation', 'still-present original process', 'truncated pinned key', 'lost durable predecessor', 'stale receipt body', 'valid signed stale receipt', 'validStale.ManagedPlanSHA256 = strings.Repeat("f", 64)', 'verifyOwnedStopReceipt(validStaleRaw, public, originalWire, secret)', 'same-length changed pinned key', 'missing receipt', 'unsafe owned path chain', 'wrong directory owner', 'wrong receipt owner', 'linked receipt inode', 'receipt changed during held read', 'original process state uncertain', 'validly signed original operation mismatch', 'validly signed original step mismatch', 'operation fence', 'missing durable result', 'pinned root key', 'prior receipt digest', 'prior receipt signature', 'original command signature', 'noncanonical original command']) if (!priorControls.includes(token)) throw new Error('actual durable prior-result controls omit a targeted authority mismatch');
  const signedMismatchControls = uniqueSourceRegion(priorControls, '\tmutateSignedOriginalLink :=', '\tmutateAndRejectExpected("validly signed original operation mismatch"');
  for (const token of ['wsproto.VerifyCommand(original', 'wsproto.CanonicalCommandEnvelope(original)', 'CommandSigningMaterialForOwnedStop(original)', 'changedReceipt.SigningMaterialSHA256 = sha256Hex(changedMaterial)', 'changedReceipt.OperationID =', 'changedReceipt.StepID =', 'verifyOwnedStopReceipt(*raw, ed25519.PublicKey(*public), wire, secret)']) if (!signedMismatchControls.includes(token)) throw new Error('signed operation/step mismatch controls leave an original signed receipt link unsynchronized');
  const signedCommandAt = signedMismatchControls.indexOf('wsproto.VerifyCommand(original');
  const signedReceiptAt = signedMismatchControls.indexOf('verifyOwnedStopReceipt(*raw, ed25519.PublicKey(*public), wire, secret)');
  const signedCaseAt = priorControls.indexOf('mutateAndRejectExpected("validly signed original operation mismatch"');
  if (signedCommandAt < 0 || signedReceiptAt <= signedCommandAt || signedCaseAt <= priorControls.indexOf('mutateSignedOriginalLink :=')) throw new Error('operation/step mismatch fixture does not independently validate its signed original command and receipt before intended rejection');
  const missingOpPositive = priorControls.indexOf('known owned-IO cold wrapper path was rejected');
  const missingOpNegative = priorControls.indexOf('missingOperationState := copyColdState()', missingOpPositive);
  const coldFailures = priorControls.indexOf('for _, failure := range []struct {', missingOpNegative);
  if (missingOpPositive < 0 || missingOpNegative <= missingOpPositive || coldFailures <= missingOpNegative || !priorControls.includes('for _, phase := range []string') || !priorControls.includes('coldReadCounts[phase] != 1') || !priorControls.includes('badState := copyColdState()') || !priorControls.includes('checkpointPlanBrokerColdPriorStopReceiptWithIO(paths, copyColdState(), plan, secret, failure.io)')) throw new Error('owned-IO positive/read reachability and isolated copied negatives are not ordered before later failures');
  const staleReceiptAt = priorControls.indexOf('validStale.ManagedPlanSHA256 = strings.Repeat("f", 64)');
  const staleVerifyAt = priorControls.indexOf('verifyOwnedStopReceipt(validStaleRaw, public, originalWire, secret)', staleReceiptAt);
  const staleIOAt = priorControls.indexOf('{"valid signed stale receipt", makeColdIO(', staleVerifyAt);
  if (staleReceiptAt < 0 || staleVerifyAt <= staleReceiptAt || staleIOAt <= staleVerifyAt || priorControls.includes('validStale.ModelAlias =')) throw new Error('stale receipt positive is not a fully valid original-command receipt with an independently changed managed digest before the targeted old-digest rejection');
  const cpuControls = uniqueSourceRegion(cpuFixture, 'func verifyPlanBrokerCPUStoppedSampleControls() error {', '\nfunc readPlanBrokerCPUReceipt(');
  for (const token of ['complete loaded stopped proof positive', 'exact not-found cleanup proof positive', 'not-found cannot authorize loaded proof', 'live original process', 'zombie original process', 'unavailable original process', 'pending exact unit job', 'malformed job inventory', 'nonempty old cgroup', 'unavailable old cgroup', 'foreign old cgroup']) if (!cpuControls.includes(token)) throw new Error('actual Go stop/cleanup controls omit a required known positive or targeted rejection');
  const nodeClientTest = uniqueSourceRegion(cpuFixture, 'func TestCheckpointPlanRelaunchCPUNodeClient(t *testing.T) {', '\nfunc seedPlanBrokerCPUDurableStopResult(');
  const seedResult = uniqueSourceRegion(cpuFixture, 'func seedPlanBrokerCPUDurableStopResult(', '\nfunc makePlanBrokerCPUQuery(');
  for (const token of ['seedPlanBrokerCPUDurableStopResult(processor, seed.Command, seed.Receipt, paths, secret)', 'processor.save()']) if (!nodeClientTest.includes(token)) throw new Error('both fixture predecessors are not seeded and saved in the existing NodeClient lifecycle');
  const victimBranch = uniqueSourceRegion(nodeClientTest, '\tif phase == "urgent_load" {', '\t} else {');
  const urgentBranchStart = nodeClientTest.indexOf('\n\t} else {', nodeClientTest.indexOf('if phase == "urgent_load" {'));
  const handleAt = nodeClientTest.indexOf('\n\tresult := processor.Handle(context.Background(), command)', urgentBranchStart);
  const urgentBranch = urgentBranchStart < 0 || handleAt <= urgentBranchStart ? '' : nodeClientTest.slice(urgentBranchStart, handleAt);
  if (!victimBranch.includes('processor.save()') || !victimBranch.includes('len(processor.pending) != 0 || len(processor.inflight) != 0') || !victimBranch.includes('processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "victim_stop", secret, seed.Receipt, expectedHeld)') ||
      !urgentBranch.includes('processor.save()') || !urgentBranch.includes('len(processor.pending) != 0 || len(processor.inflight) != 0') || !urgentBranch.includes('processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "urgent_stop", secret, seed.Receipt, expectedHeld)')) throw new Error('both predecessor roles must save an idle state, reload, and use the actual persisted processor before Handle');
  const readbackHelper = uniqueSourceRegion(cpuFixture, 'func verifySavedReadbackPlanBrokerCPUPredecessor(', '\nfunc seedPlanBrokerCPUDurableStopResult(');
  for (const token of ['expectedReceiptRaw []byte', 'expectedHeld planBrokerCPULaunchIdentity', 'verifyOwnedStopReceipt(expectedReceiptRaw,', 'verifyPlanBrokerCPUStopReceiptBinding(expectedHeld, expectedReceipt)', 'newCommandProcessor(cfg,', 'reloaded.initError != nil || reloaded.stateBlocked || len(reloaded.pending) != 0 || len(reloaded.inflight) != 0 || !reloaded.ready.Load()', 'reloaded.commandStatePayload()', 'verifyCheckpointPlanBrokerPriorStopResult(readback,', 'verifyOwnedStopReceipt(receiptRaw, public, mustPlanBrokerWire(priorCommand), secret)', 'bytes.Equal(receiptRaw, expectedReceiptRaw)', 'verifyPlanBrokerCPUStopReceiptBinding(expectedHeld, stored)', 'durable prior stop result is unavailable', 'durable prior stop result no longer matches its pinned command and receipt', '"plan":', '"incarnation":', '"custody":', '"alias":', 'return reloaded']) if (!readbackHelper.includes(token)) throw new Error('saved/reloaded predecessor helper omits independent expected binding, accepted checksum/journal state, fresh readback, returned processor, or intended drift controls');
  if (readbackHelper.indexOf('newCommandProcessor(cfg,') > readbackHelper.indexOf('verifyCheckpointPlanBrokerPriorStopResult(readback,') || nodeClientTest.indexOf('processor = verifySavedReadbackPlanBrokerCPUPredecessor(') > nodeClientTest.indexOf('result := processor.Handle(context.Background(), command)')) throw new Error('saved predecessor validation does not precede actual command Handle on the reloaded processor');
  const heldHelperCalls = ['processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "victim_stop", secret, seed.Receipt, expectedHeld)', 'processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "urgent_stop", secret, seed.Receipt, expectedHeld)'];
  if (!cpuFixture.startsWith('//go:build linux && checkpoint_plan_broker_cpu\n') || !brokerTest.startsWith('//go:build linux\n') || /planBrokerCPULaunchIdentity|verifyPlanBrokerCPUStopReceiptBinding/.test(brokerTest)) throw new Error('ordinary/tagged test declaration closure is not build-tag safe');
  for (const token of ['processor.results[command.ID] = result', 'processor.results["key:"+command.IdempotencyKey] = result', 'mustReadPlanBrokerCPUStopPublic(paths)', 'verifyOwnedStopReceipt(receipt, public, wire, secret)', 'wsproto.CanonicalCommandEnvelope(command)', 'processor.semanticFingerprint(command)']) if (!seedResult.includes(token)) throw new Error('fixture predecessor is not an exact successful signed durable result');
  const ackBody = uniqueSourceRegion(cpuFixture, 'func makePlanBrokerCPUStopAck(', '\nfunc writePlanBrokerCPUStopAck(');
  for (const token of ['held.CurrentIncarnation', 'held.PlanSHA256', 'held.CustodyBindingSHA256', 'held.Alias', 'receipt.ManagedCurrentIncarnation = held.CurrentIncarnation', 'receipt.ManagedPlanSHA256 = held.PlanSHA256', 'receipt.ModelAlias = held.Alias']) if (!ackBody.includes(token)) throw new Error('synthetic stop receipt promotes placeholders instead of the held managed binding');
  for (const owner of ['TestCheckpointPlanRelaunchCPULifecycleSequence', 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect']) {
    const next = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {' : 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {';
    const region = uniqueSourceRegion(cpuFixture, 'func ' + owner + '(t *testing.T) {', next);
    const holdAt = region.indexOf('victimPIDFD, err := holdPlanBrokerCPUTerminalPIDFD(victimLaunch)');
    const unitVar = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'unitIdentity' : 'unitName';
    const stopAt = region.indexOf(`if err := stopPlanBrokerCPUUnit(${unitVar});`, holdAt);
    const waitAt = region.indexOf('waitPlanBrokerCPUStoppedProof(paths, victimLaunch, victimPIDFD)');
    const ackAt = region.indexOf('makePlanBrokerCPUStopAck(paths, "victim_stop", victimBefore, victimLaunch, victimPIDFD');
    if (holdAt < 0 || stopAt <= holdAt || waitAt <= stopAt || ackAt <= waitAt) throw new Error('CPU fixture does not order hold → stop → terminal proof → synthetic ACK');
    const cleanupAt = region.indexOf('cleanup := func() error {');
    const cleanupEnd = region.indexOf('\n\tdefer func() {', cleanupAt);
    const cleanup = cleanupAt < 0 || cleanupEnd <= cleanupAt ? '' : region.slice(cleanupAt, cleanupEnd);
    const cleanupHoldAt = cleanup.indexOf('holdPlanBrokerCPUTerminalPIDFD(held)');
    const cleanupStopAt = cleanup.indexOf('stopPlanBrokerCPUUnit(', cleanupHoldAt);
    const cleanupProofAt = cleanup.indexOf('waitPlanBrokerCPUStoppedCleanupProof(paths, held, pidfd)', cleanupHoldAt);
    const cleanupAbsentAt = cleanup.indexOf('confirmPlanBrokerCPUUnitAbsentWithin(paths,', cleanupProofAt);
    const closeHeldAt = cleanup.indexOf('for invocation, pidfd := range heldPIDFDs');
    if (cleanupHoldAt < 0 || cleanupProofAt <= cleanupHoldAt || cleanupAbsentAt <= cleanupProofAt || closeHeldAt <= cleanupAbsentAt || !cleanup.includes('unix.Close(pidfd)') || (cleanupStopAt >= 0 && cleanupStopAt <= cleanupHoldAt) || region.includes('defer unix.Close(victimPIDFD)') || region.includes('defer unix.Close(urgentPIDFD)')) throw new Error(`${owner} cleanup does not retain/open its exact pidfd through terminal/job/cgroup proof and close it only afterward`);
  }
  const closeControl = uniqueSourceRegion(cpuFixture, 'func closePlanBrokerCPUOpenedPIDFD(', '\nfunc planBrokerCPUWorkerEmptyDiagnosticCode(');
  const successCloseAt = closeControl.indexOf('settlePlanBrokerCPUOpenedPIDFDClose(nil, 41,');
  const injectedCloseAt = closeControl.indexOf('closeErr := errors.New("injected close failure")');
  if (!closeControl.includes('closeFD(pidfd)') || !closeControl.includes('verifyPlanBrokerCPUOpenedPIDFDCloseControls()') || !closeControl.includes('errors.Is(outcome, priorProof)') || !closeControl.includes('errors.Is(outcome, closeErr)') || !closeControl.includes('errors.Join(outcome, errors.New("cleanup-opened worker pidfd close failed; preserving private fixture"), closeErr)') || successCloseAt < 0 || injectedCloseAt <= successCloseAt) throw new Error('opened-here pidfd close success must precede the joined failure control');
  for (const owner of ['TestCheckpointPlanRelaunchCPULifecycleSequence', 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect']) {
    const next = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {' : 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {';
    const region = uniqueSourceRegion(cpuFixture, `func ${owner}(t *testing.T) {`, next);
    const outcomeAssignment = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence'
      ? 'cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(cleanupErr, pidfd, unix.Close))'
      : 'result = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(result, pidfd, unix.Close))';
    const openedClose = region.indexOf(outcomeAssignment);
    const preservationGate = region.indexOf(owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'if cleanupErr == nil && privateOwned {' : 'if result == nil && privateOwned {', openedClose);
    const proof = region.lastIndexOf('waitPlanBrokerCPUStoppedCleanupProof(paths, held, pidfd)', openedClose);
    const absence = region.lastIndexOf('confirmPlanBrokerCPUUnitAbsentWithin(paths,', openedClose);
    if (openedClose < 0 || proof < 0 || absence < proof || openedClose < absence || preservationGate <= openedClose) throw new Error(`${owner} cleanup owner does not consume joined opened-here close outcome after proof`);
  }
  return true;
}

function selfTestStoppedStateProofSource(broker, brokerTest, cpuFixture) {
  validateStoppedStateProofSource(broker, brokerTest, cpuFixture);
  const once = (text, before, after) => {
    if (text.split(before).length !== 2) throw new Error('stopped-proof mutant anchor is not exact-once');
    return text.replace(before, after);
  };
  const reject = (mutant, label, slot = 0, expectedCategory = '') => {
    const candidates = [broker, brokerTest, cpuFixture];
    candidates[slot] = mutant;
    let reason = '';
    try { validateStoppedStateProofSource(candidates[0], candidates[1], candidates[2]); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason || (expectedCategory && !reason.includes(expectedCategory))) throw new Error(`stopped-proof control ${label} did not reject in slot ${slot} with ${expectedCategory || 'a targeted source category'}: ${reason || 'accepted'}`);
  };
  const parserTestRegion = uniqueSourceRegion(brokerTest, 'func TestPlanBrokerUnitParserRequiresCompleteFixedProperties(t *testing.T) {', '\nfunc TestPlanBrokerJobParserUsesExactUnitIdentity(');
  const derivedUnitName = 'checkpointPlanBrokerUnitName(checkpointPlanBrokerPaths{})';
  reject(brokerTest.replace(parserTestRegion, once(parserTestRegion, derivedUnitName, '"vram-governor-llama-server.service"')), 'stale hard-coded parser fixture unit', 1, 'derived exact-unit identity');
  reject(brokerTest.replace(parserTestRegion, once(parserTestRegion, 'wrongPrior.ControlGroup = filepath.Join("/system.slice", "other.service")', 'wrongPrior.ControlGroup = unitControlGroup')), 'omitted exact prior cgroup negative', 1, 'derived exact-unit identity');
  reject(brokerTest.replace(parserTestRegion, once(parserTestRegion, 'activeUnit.MainPID != 42 || activeUnit.Active != "active" || activeUnit.Invocation == "" || activeUnit.ControlGroup != unitControlGroup', 'false')), 'omitted active MainPID positive assertion', 1, 'derived exact-unit identity');
  reject(once(broker, 'values["LoadState"] != "loaded"', 'false'), 'not-found loaded-state bypass', 0, 'bounded six-field stopped observation');
  reject(once(broker, 'invocationEmpty != groupEmpty', 'false'), 'one-empty identity bypass', 0, 'stopped state no longer requires the signed prior identity pair');
  reject(once(broker, 'observed.ControlGroup != prior.ControlGroup', 'false'), 'wrong signed cgroup join', 0, 'stopped state no longer requires the signed prior identity pair');
  const terminalRegion = uniqueSourceRegion(broker, 'func checkpointPlanBrokerOriginalWorkerTerminalResult(', 'func checkpointPlanBrokerStoppedWorkerEmpty(');
  reject(broker.replace(terminalRegion, once(terminalRegion, 'errors.Is(procErr, os.ErrNotExist)', 'false')), 'missing original incarnation absence proof', 0, 'original PID/start terminal proof');
  reject(once(broker, 'bytes.Equal(resultPublic, pinnedPublic)', 'true'), 'changed prior stop public-key pin', 0, 'prior command/key/receipt/fence authority join');
  reject(once(broker, 'resultDigest != sha256Hex(receiptRaw)', 'false'), 'changed prior stop receipt digest', 0, 'prior command/key/receipt/fence authority join');
  reject(once(broker, 'verifyOwnedStopReceipt(receiptRaw, pinnedPublic, originalWire, secret)', 'nil'), 'missing full prior signed receipt verification', 0, 'prior command/key/receipt/fence authority join');
  const priorRegion = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerPriorStopResult(', '\nfunc checkpointPlanBrokerColdPriorStopReceipt(');
  reject(broker.replace(priorRegion, once(priorRegion, 'operation.Fence != fence', 'false')), 'missing actual operation fence comparison', 0, 'prior command/key/receipt/fence authority join');
  const proofSampleRegion = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStoppedWorkerEmptySample(', '\nfunc parseCheckpointPlanBrokerUnitState(');
  reject(broker.replace(proofSampleRegion, once(proofSampleRegion, 'if pending {', 'if false {')), 'missing pending-job success rejection', 0, 'shared stop/cleanup proof omits');
  reject(broker.replace(proofSampleRegion, once(proofSampleRegion, 'len(bytes.TrimSpace(cgroupProcs)) != 0', 'false')), 'missing nonempty old-cgroup rejection', 0, 'shared stop/cleanup proof omits');
  const coldRegion = uniqueSourceRegion(broker, 'func checkpointPlanBrokerColdPriorStopReceiptWithIO(', '\n// verifyCheckpointPlanBrokerColdPriorStopReceiptEvidence');
  reject(broker.replace(coldRegion, once(coldRegion, 'bytes.Equal(public, stopStep.PinnedRootStopPublicKey)', 'true')), 'missing cold pinned-key join', 0, 'cold owned-IO reducer');
  reject(broker.replace(coldRegion, once(coldRegion, 'sha256Hex(raw) != fmt.Sprint(command.Args["prior_receipt_sha256"])', 'false')), 'missing cold receipt digest recheck', 0, 'cold owned-IO reducer');
  reject(once(brokerTest, 'known exact cold prior-stop proof was rejected', 'known cold prior-stop proof control removed'), 'removed actual cold reducer Go control', 1, 'actual durable prior-result controls');
  reject(once(brokerTest, '\t"vram-governor/internal/wsproto"\n', ''), 'removed required ordinary-test wsproto import', 1, 'ordinary Linux broker tests are missing the wsproto package import');
  reject(once(brokerTest, '\t"fmt"\n', ''), 'removed required ordinary-test fmt import', 1, 'ordinary Linux broker tests are missing the fmt package import');
  reject(once(brokerTest, 'OwnedStopOperations: map[string]ownedStopOperationState{"gpu-0": persistedOperation}', ''), 'removed exact operation setup from owned-IO positive', 1, 'actual durable prior-result controls');
  reject(once(brokerTest, 'validStale.ManagedPlanSHA256 = strings.Repeat("f", 64)', 'validStale.ModelAlias = "other-model"'), 'stale receipt changed to command-bound alias mismatch', 1, 'actual durable prior-result controls');
  reject(once(brokerTest, 'changedReceipt.SigningMaterialSHA256 = sha256Hex(changedMaterial)', 'changedReceipt.SigningMaterialSHA256 = ""'), 'stale original signing-material link in op/step mutant', 1, 'signed operation/step mismatch controls leave an original signed receipt link unsynchronized');
  reject(once(brokerTest, 'changedReceipt.OperationID = fmt.Sprint(original.Args["operation_id"])', ''), 'stale operation identity in signed op/step mutant', 1, 'signed operation/step mismatch controls leave an original signed receipt link unsynchronized');
  reject(once(brokerTest, 'verifyOwnedStopReceipt(*raw, ed25519.PublicKey(*public), wire, secret)', 'nil'), 'removed independent full signed receipt validation in op/step mutant', 1, 'signed operation/step mismatch controls leave an original signed receipt link unsynchronized');
  reject(once(brokerTest, 'package nodeagent', 'var _ planBrokerCPULaunchIdentity\n\npackage nodeagent'), 'ordinary test references tagged-only held binding', 1, 'ordinary Linux broker tests reference a checkpoint_plan_broker_cpu-only declaration');
  reject(once(cpuFixture, '//go:build linux && checkpoint_plan_broker_cpu', '//go:build linux'), 'removed opt-in tag from CPU-only declaration owner', 2, 'CPU owner fixture lost its exact opt-in build constraint');
  const heldHelperCalls = ['processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "victim_stop", secret, seed.Receipt, expectedHeld)', 'processor = verifySavedReadbackPlanBrokerCPUPredecessor(t, cfg, paths, command, seed.Command, "urgent_stop", secret, seed.Receipt, expectedHeld)'];
  for (const call of heldHelperCalls) reject(once(cpuFixture, call, '// tagged readback-helper call removed'), `omitted saved/reloaded predecessor role ${call.includes('victim_stop') ? 'victim' : 'urgent'}`, 2, 'both predecessor roles must save an idle state, reload, and use the actual persisted processor before Handle');
  const readbackRegion = uniqueSourceRegion(cpuFixture, 'func verifySavedReadbackPlanBrokerCPUPredecessor(', '\nfunc seedPlanBrokerCPUDurableStopResult(');
  reject(cpuFixture.replace(readbackRegion, once(readbackRegion, 'newCommandProcessor(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), true)', 'processor')), 'replaced fresh saved-state processor reload', 2, 'saved/reloaded predecessor helper omits independent expected binding, accepted checksum/journal state, fresh readback, returned processor, or intended drift controls');
  reject(cpuFixture.replace(readbackRegion, once(readbackRegion, 'verifyCheckpointPlanBrokerPriorStopResult(readback, paths, planCommand, operation, step, receiptRaw, public, secret)', 'nil')), 'removed persisted result authority verification', 2, 'saved/reloaded predecessor helper omits independent expected binding, accepted checksum/journal state, fresh readback, returned processor, or intended drift controls');
  reject(cpuFixture.replace(readbackRegion, once(readbackRegion, '!reloaded.ready.Load()', 'false')), 'accepted reload without successful readiness/current journal state', 2, 'saved/reloaded predecessor helper omits independent expected binding, accepted checksum/journal state, fresh readback, returned processor, or intended drift controls');
  const markerRegion = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUInactiveWaitMarker(', '\nfunc closePlanBrokerCPUOpenedPIDFD(');
  reject(cpuFixture.replace(markerRegion, once(markerRegion, '"pid_state_shape", "unit_definition_missing",', '"pid_state_shape",')), 'removed not-found marker allowlist entry', 2, 'Go inactive wait marker');
  reject(once(cpuFixture, 'if n != 1 || !planBrokerCPUTerminalPollEventsValid(descriptor[0].Revents) {', 'if n != 1 {'), 'removed actual PIDFD readiness mask predicate', 2, 'PIDFD terminal proof');
  reject(once(cpuFixture, 'PlanSHA256: binding.PlanSHA256', 'PlanSHA256: sha256Hex(mustJSON(plan))'), 'replaced observed held managed-plan digest with a template recomputation', 2, 'held managed-plan digest');
  const pollMaskRegion = uniqueSourceRegion(cpuFixture, 'func planBrokerCPUTerminalPollEventsValid(', '\nfunc runPlanBrokerCPUParentDeathHelper(');
  reject(cpuFixture.replace(pollMaskRegion, once(pollMaskRegion, 'revents&int16(unix.POLLIN) == 0', 'false')), 'accepted missing POLLIN requirement', 2, 'terminal event mask');
  reject(cpuFixture.replace(pollMaskRegion, once(pollMaskRegion, 'revents&int16(unix.POLLERR|unix.POLLNVAL) != 0', 'false')), 'accepted pidfd error flags', 2, 'terminal event mask');
  reject(cpuFixture.replace(pollMaskRegion, once(pollMaskRegion, 'revents & ^allowed != 0', 'false')), 'accepted unknown pidfd flags', 2, 'terminal event mask');
  for (const owner of ['TestCheckpointPlanRelaunchCPULifecycleSequence', 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect']) {
    const next = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {' : 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {';
    const ownerRegion = uniqueSourceRegion(cpuFixture, `func ${owner}(t *testing.T) {`, next);
    const cleanupAt = ownerRegion.indexOf('cleanup := func() error {');
    const cleanupEnd = ownerRegion.indexOf('\n\tdefer func() {', cleanupAt);
    if (cleanupAt < 0 || cleanupEnd <= cleanupAt) throw new Error('cleanup control region is missing for exact CPU fixture owner');
    const cleanup = ownerRegion.slice(cleanupAt, cleanupEnd);
    reject(cpuFixture.replace(ownerRegion, ownerRegion.replace(cleanup, once(cleanup, 'waitPlanBrokerCPUStoppedCleanupProof(paths, held, pidfd)', 'nil'))), `${owner} cleanup proof omission`, 2, 'cleanup does not retain/open');
    reject(cpuFixture.replace(ownerRegion, ownerRegion.replace(cleanup, once(cleanup, 'for invocation, pidfd := range heldPIDFDs {', 'if false {'))), `${owner} closes held pidfds only after proof`, 2, 'cleanup does not retain/open');
    const outcomeAssignment = owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence'
      ? 'cleanupErr = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(cleanupErr, pidfd, unix.Close))'
      : 'result = planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, settlePlanBrokerCPUOpenedPIDFDClose(result, pidfd, unix.Close))';
    reject(cpuFixture.replace(ownerRegion, ownerRegion.replace(cleanup, once(cleanup, outcomeAssignment, `_ = settlePlanBrokerCPUOpenedPIDFDClose(${owner === 'TestCheckpointPlanRelaunchCPULifecycleSequence' ? 'cleanupErr' : 'result'}, pidfd, unix.Close)`))), `${owner} ignored joined opened-here close outcome`, 2, 'cleanup owner does not consume joined opened-here close outcome');
  }
  const publishRegion = uniqueSourceRegion(broker, 'func publishCheckpointPlanBrokerPlan(', 'func awaitCheckpointPlanBrokerBinding(');
  reject(broker.replace(publishRegion, once(publishRegion, 'checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)', 'nil')), 'missing pre-CAS stopped proof', 0, 'fresh stopped proof does not precede plan CAS');
  const startRegion = uniqueSourceRegion(broker, 'func verifyCheckpointPlanBrokerStartState(', 'func mustPlanBrokerPublicKey(');
  reject(broker.replace(startRegion, once(startRegion, 'checkpointPlanBrokerStoppedWorkerEmpty(ctx, paths, prior)', 'nil')), 'missing pre-start stopped proof', 0, 'fresh stopped proof does not precede first start');
  let fixtureMutant = once(cpuFixture, 'unix.PidfdOpen(held.PID, 0)', 'unix.PidfdOpen(held.PID+1, 0)');
  reject(fixtureMutant, 'different worker PIDFD', 2, 'CPU fixture does not hold the exact live worker PIDFD');
  return true;
}

function validateTransport14FailureClassifierSource(source) {
  const ownersAt = source.indexOf('\nconst inactiveWaitOwners = [');
  const codesAt = source.indexOf('\nconst inactiveWaitCodes = new Set([', ownersAt + 1);
  if (ownersAt < 0 || codesAt <= ownersAt || source.indexOf('\nconst inactiveWaitOwners = [', ownersAt + 1) >= 0) throw new Error('inactive wait owner source is missing or ambiguous');
  const owners = source.slice(ownersAt + 1, codesAt + 1);
  if (owners !== 'const inactiveWaitOwners = [\n  \'TestCheckpointPlanRelaunchCPULifecycleSequence\',\n  \'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect\',\n];\n') throw new Error('inactive wait classifier owner set must remain the exact two owning top tests');
  const classifierAt = source.indexOf('\nfunction classifyInactiveWaitFailure(', codesAt + 1);
  if (classifierAt <= codesAt || source.indexOf('\nconst inactiveWaitCodes = new Set([', codesAt + 1) >= 0) throw new Error('inactive wait code source is missing or ambiguous');
  const codes = source.slice(codesAt + 1, classifierAt + 1);
  const codeNames = [...codes.matchAll(/'([a-z_]+)'/g)].map((match) => match[1]);
  const expectedCodes = ['private_binding', 'show_unavailable', 'show_envelope', 'state_parse', 'empty_invocation', 'empty_control_group', 'empty_invocation_control_group', 'pid_state_shape', 'nonzero_pid', 'invocation_mismatch', 'unit_definition_missing', 'worker_state', 'jobs_unavailable', 'jobs_malformed', 'pending_job', 'cgroup_unconfirmed', 'unavailable'];
  if (JSON.stringify(codeNames) !== JSON.stringify(expectedCodes)) throw new Error('inactive wait classifier code set must be exact and finite');
  const classifier = uniqueSourceRegion(source, 'function classifyInactiveWaitFailure(output, expected) {', '\nfunction selfTestInventory(');
  for (const required of [
    "const expectedOwners = inactiveWaitOwners.filter((name) => expected.includes(name));",
    "const lifecycle = [];",
    "const malformedLifecycle = lifecycle.some((event) => event.kind === 'malformed');",
    "malformedRun || malformedFailure || malformedLifecycle ||",
    "const run = line.match(/^=== RUN   (\\S+)$/);",
    "const match = line.match(/^--- FAIL: (\\S+) \\((?:\\d+(?:\\.\\d+)?s)\\)$/);",
    "const interveningLifecycle = lifecycle.some((event) => event.lineIndex > starts[0] && event.lineIndex < ends[0]);",
    "const contradictoryOwnerCompletion = lifecycle.some((event) => event.name === name && (event.kind === 'PASS' || event.kind === 'SKIP'));",
    "line.includes('__PLAN_RELAUNCH_INACTIVE_WAIT__')",
    "line.match(/^__PLAN_RELAUNCH_INACTIVE_WAIT__:([A-Za-z0-9_]+):([a-z_]+)$/)",
    'inactiveWaitOwners.includes(match[1])', 'expectedOwners.includes(match[1])', 'inactiveWaitCodes.has(match[2])',
    'found.has(match[1])', 'starts[0] < markerIndex && markerIndex < ends[0]', 'interveningLifecycle || contradictoryOwnerCompletion', "return 'inactive_wait=unavailable'",
  ]) if (!classifier.includes(required)) throw new Error(`failure classifier is missing ${required}`);
  if ((classifier.match(/malformedLifecycle/g) ?? []).length !== 2) throw new Error('global malformed lifecycle guard must be declared and consumed exactly once');
  const inventory = uniqueSourceRegion(source, 'function executeInventory(', '\nfunction withPrivateBinary(');
  const failureAt = inventory.indexOf('if (result.status !== 0)');
  const failureEnd = inventory.indexOf('\n  try { exactInventory', failureAt);
  if (failureAt < 0 || failureEnd <= failureAt || inventory.indexOf('if (result.status !== 0)', failureAt + 1) >= 0) throw new Error('inventory failure branch is missing or ambiguous');
  const failureBranch = inventory.slice(failureAt, failureEnd);
  const optInAt = failureBranch.indexOf('if (optIn) {');
  const defaultWriteAt = failureBranch.indexOf('process.stderr.write(output)');
  const optInEnd = failureBranch.indexOf('\n    }\n    process.stderr.write(output);', optInAt);
  const optInBranch = optInAt < 0 || optInEnd <= optInAt ? '' : failureBranch.slice(optInAt, optInEnd);
  if (!optInBranch.includes('classifyInactiveWaitFailure(output, expected)') ||
      !optInBranch.includes('preservePrivateWorkspace = true') || !optInBranch.includes('diagnostic') ||
      optInBranch.includes('process.stderr.write(output)') || defaultWriteAt <= optInEnd) throw new Error('opt-in inventory failures must emit only the finite owning-test classification and preserve the workspace');
  if ((optInBranch.match(/classifyInactiveWaitFailure\(output, expected\)/g) ?? []).length !== 1) throw new Error('opt-in failure classifier must run exactly once');
  return true;
}

function selfTestTransport14FailureClassifier(source) {
  validateTransport14FailureClassifierSource(source);
  const owner = inactiveWaitOwners[0];
  const good = `=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n--- FAIL: ${owner} (0.10s)\n`;
  if (classifyInactiveWaitFailure(good, inactiveWaitOwners) !== `${owner}=nonzero_pid`) throw new Error('finite inactive-wait marker known-positive did not classify exactly');
  const emptyGroupGood = good.replace(':nonzero_pid', ':empty_control_group');
  if (classifyInactiveWaitFailure(emptyGroupGood, inactiveWaitOwners) !== `${owner}=empty_control_group`) throw new Error('complete-envelope empty ControlGroup code did not classify as a fixed positive');
  for (const code of ['empty_invocation', 'empty_invocation_control_group', 'pid_state_shape', 'unit_definition_missing']) {
    if (classifyInactiveWaitFailure(good.replace(':nonzero_pid', `:${code}`), inactiveWaitOwners) !== `${owner}=${code}`) throw new Error(`finite state-shape diagnostic code was not accepted: ${code}`);
  }
  for (const actualOwner of inactiveWaitOwners) {
    const capturedNotFoundMarker = `__PLAN_RELAUNCH_INACTIVE_WAIT__:${actualOwner}:unit_definition_missing`;
    const capturedNotFoundOutput = `=== RUN   ${actualOwner}\n${capturedNotFoundMarker}\n--- FAIL: ${actualOwner} (0.10s)\n`;
    if (classifyInactiveWaitFailure(capturedNotFoundOutput, inactiveWaitOwners) !== `${actualOwner}=unit_definition_missing`) throw new Error(`actual owning marker path did not retain not-found diagnostic for ${actualOwner}`);
  }
  const twoGood = `=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:state_parse\n--- FAIL: ${owner} (0.10s)\n=== RUN   ${inactiveWaitOwners[1]}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${inactiveWaitOwners[1]}:jobs_unavailable\n--- FAIL: ${inactiveWaitOwners[1]} (0.20s)\n`;
  if (classifyInactiveWaitFailure(twoGood, inactiveWaitOwners) !== `${owner}=state_parse;${inactiveWaitOwners[1]}=jobs_unavailable`) throw new Error('two-owner failure diagnostics did not bind in failed-test order');
  const otherPassedOutside = `=== RUN   TestOtherSelectedBefore\n--- PASS: TestOtherSelectedBefore (0.01s)\n${good}=== RUN   TestOtherSelectedAfter\n--- PASS: TestOtherSelectedAfter (0.02s)\n`;
  if (classifyInactiveWaitFailure(otherPassedOutside, [...inactiveWaitOwners, 'TestOtherSelectedBefore', 'TestOtherSelectedAfter']) !== `${owner}=nonzero_pid`) throw new Error('successful selected tests outside the owning failure interval were not preserved');
  const malformedOutside = [
    `=== RUN   TestMalformedBefore\n--- PASS: TestMalformedBefore\n${good}`,
    `=== RUN   TestMalformedBefore\n--- SKIP: TestMalformedBefore\n${good}`,
    `=== NAME  TestMalformedBefore\n${good}`,
    ` --- PASS: TestMalformedBefore (0.01s)\n${good}`,
    `=== RUN   TestMalformedAfter\n--- PASS: TestMalformedAfter (0.01s) trailing-junk\n${good}`,
    `${good}=== NAME  TestMalformedAfter\n`,
  ];
  for (const mutant of malformedOutside) if (classifyInactiveWaitFailure(mutant, [...inactiveWaitOwners, 'TestMalformedBefore', 'TestMalformedAfter']) !== 'inactive_wait=unavailable') throw new Error('failure classifier accepted malformed lifecycle outside owner interval');
  const crossPhase = `=== RUN   ${owner}\n=== RUN   ${inactiveWaitOwners[1]}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:state_parse\n--- FAIL: ${owner} (0.10s)\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${inactiveWaitOwners[1]}:jobs_unavailable\n--- FAIL: ${inactiveWaitOwners[1]} (0.20s)\n`;
  const invalid = [
    good.replace(`__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, ''),
    good.replace(`__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid`, `__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid`),
    good.replace(':nonzero_pid', ':private_path=/secret/pid=1234'),
    good.replace(`__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid`, `__PLAN_RELAUNCH_INACTIVE_WAIT__:${inactiveWaitOwners[1]}:nonzero_pid`),
    good.replace(':nonzero_pid', ':unknown_code'),
    good.replace(`--- FAIL: ${owner}`, `--- PASS: ${owner}`),
    good.replace(`--- FAIL: ${owner}`, '--- FAIL: TestUnownedFixture'),
    `${good}__PLAN_RELAUNCH_INACTIVE_WAIT__:${inactiveWaitOwners[1]}:nonzero_pid\n`,
    good.replace(' (0.10s)', ''),
    good.replace(`=== RUN   ${owner}\n`, ''),
    good.replace(`=== RUN   ${owner}\n`, `=== RUN   ${owner}\n=== RUN   ${owner}\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `=== RUN   ${owner}\n=== RUN   TestForeignBetweenOwnerAndMarker\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    good.replace(`=== RUN   ${owner}\n`, `=== RUN ${owner}\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `=== RUN   ${owner}\n--- PASS: ${owner} (0.00s)\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `=== RUN   ${owner}\n=== RUN   ${owner}/nested\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `=== RUN   ${owner}\n--- SKIP: TestForeignBetweenOwnerAndMarker (0.00s)\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `=== RUN   ${owner}\n=== NAME  ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    good.replace(`=== RUN   ${owner}\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`, `__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n=== RUN   ${owner}\n`),
    good.replace(`__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n--- FAIL: ${owner}`, `--- FAIL: ${owner}`).replace(` (0.10s)\n`, ` (0.10s)\n__PLAN_RELAUNCH_INACTIVE_WAIT__:${owner}:nonzero_pid\n`),
    crossPhase,
  ];
  for (const mutant of invalid) if (classifyInactiveWaitFailure(mutant, inactiveWaitOwners) !== 'inactive_wait=unavailable') throw new Error('failure classifier accepted missing, duplicate, malformed, private, wrong-owner, unknown, or unbound diagnostic');
  const bypass = source.replace('\n      const diagnostic = classifyInactiveWaitFailure(output, expected);', "\n      const diagnostic = 'inactive_wait=unavailable';");
  if (bypass === source) throw new Error('failure-classifier consumption mutant anchor is absent');
  let bypassRejected = false;
  try { validateTransport14FailureClassifierSource(bypass); } catch { bypassRejected = true; }
  if (!bypassRejected) throw new Error('failure source controls accepted bypassed finite classifier consumption');
  for (const [before, after, label] of [
    ["const interveningLifecycle = lifecycle.some((event) => event.lineIndex > starts[0] && event.lineIndex < ends[0]);", 'const interveningLifecycle = false;', 'intervening lifecycle guard'],
    ['malformedLifecycle || ', '', 'global malformed lifecycle guard'],
    [String.raw`const run = line.match(/^=== RUN   (\S+)$/);`, String.raw`const run = line.match(/^\s*=== RUN\s+(\S+)\s*$/);`, 'exact RUN spelling'],
    ["const contradictoryOwnerCompletion = lifecycle.some((event) => event.name === name && (event.kind === 'PASS' || event.kind === 'SKIP'));", 'const contradictoryOwnerCompletion = false;', 'contradictory owner completion guard'],
    ['!(starts[0] < markerIndex && markerIndex < ends[0]) ||', 'false ||', 'marker outside owning RUN/FAIL interval'],
    ['process.stderr.write(`bounded WSL test oracle exited ${result.status ?? \'without a status\'}; ${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\\n`);', 'process.stderr.write(output);', 'raw opt-in output forwarding'],
  ]) {
    const mutant = source.replace(before, after);
    if (mutant === source) throw new Error(`failure classifier source mutant anchor is absent: ${label}`);
    let rejected = false;
    try { validateTransport14FailureClassifierSource(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`failure classifier source controls accepted ${label}`);
  }
  return true;
}

function validateOptInTestFailureSiteSource(source) {
  const filesBlock = uniqueSourceRegion(source, 'const diagnosticTestFiles = [', 'const reviewedInventoryTestNames = new Set([');
  const files = [...filesBlock.matchAll(/'([^']+_test\.go)'/g)].map((match) => match[1]);
  const expectedFiles = [
    'internal/nodeagent/checkpoint_plan_rotation_test.go',
    'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'internal/nodeagent/checkpoint_lifecycle_broker_test.go',
    'internal/nodeagent/checkpoint_lifecycle_broker_linux_test.go',
    'internal/nodeagent/commands_test.go',
    'internal/wsproto/messages_test.go',
  ];
  if (JSON.stringify(files) !== JSON.stringify(expectedFiles)) throw new Error('failure-site reducer source files exceed or differ from the fixed immutable test-file allowlist');
  const reducer = uniqueSourceRegion(source, 'function classifyOptInTestFailureSites(output, expected) {', '\nfunction validateBrokerServiceUnit(');
  for (const required of [
    "const unavailable = 'test_sites=unavailable';",
    "Buffer.byteLength(output, 'utf8') > maxFailureCaptureBytes",
    'expected.some((name) => typeof name !== \'string\' || !reviewedInventoryTestNames.has(name))',
    'new Set(expected).size !== expected.length',
    "trimmed.startsWith('===') || trimmed.startsWith('---')",
    "const run = line.match(/^=== RUN   (Test[A-Za-z0-9_]+",
    'if (!expectedSet.has(ownerName)) return unavailable;',
    'owners.size !== expected.length',
    'failedOwners.length > maxFailureOwners',
    'const goTokenCount = [...line.matchAll(/\\.go\\b/g)].length;',
    'if (goTokenCount !== matches.length) return unavailable;',
    "child.outcome === 'FAIL' && owners.get(child.owner).outcome !== 'FAIL'",
    'if (siteSet.has(siteKey)) return unavailable;',
    'siteSet.add(siteKey);',
    'siteSet.size > maxFailureSitesPerOwner',
    'sourceLine > sourceEntry[1].lineCount',
    'site.basename}:${site.sourceLine}',
    "return Buffer.byteLength(summary, 'utf8') <= maxFailureDiagnosticBytes ? summary : unavailable;",
  ]) if (!reducer.includes(required)) throw new Error(`bounded failure-site reducer is missing ${required}`);
  const inventoryNames = uniqueSourceRegion(source, 'const reviewedInventoryTestNames = new Set([', 'const maxFailureCaptureBytes =');
  const names = [...inventoryNames.matchAll(/'([^']+)'/g)].map((match) => match[1]);
  if (names.length !== 14 || new Set(names).size !== names.length || names.some((name) => !/^Test[A-Za-z0-9_]+$/.test(name))) throw new Error('failure-site reducer must validate against the fixed reviewed selected-test inventory');
  if (!source.includes('const maxFailureCaptureBytes = 8 * 1024 * 1024;') ||
      !source.includes('const maxFailureDiagnosticBytes = 8192;') ||
      !source.includes('const maxFailureOwners = 16;') ||
      !source.includes('const maxFailureSitesPerOwner = 4;') ||
      !source.includes('const maxFailureLineBytes = 64 * 1024;')) throw new Error('failure-site reducer bounds are missing or changed');

  const inventory = uniqueSourceRegion(source, 'function executeInventory(', '\nfunction withPrivateBinary(');
  const failureAt = inventory.indexOf('if (result.status !== 0)');
  const failureEnd = inventory.indexOf('\n  try { exactInventory', failureAt);
  if (failureAt < 0 || failureEnd <= failureAt || inventory.indexOf('if (result.status !== 0)', failureAt + 1) >= 0) throw new Error('opt-in failure reducer branch is missing or ambiguous');
  const failureBranch = inventory.slice(failureAt, failureEnd);
  const optInAt = failureBranch.indexOf('if (optIn) {');
  const optInEnd = failureBranch.indexOf('\n    }\n    process.stderr.write(output);', optInAt);
  const optInBranch = optInAt < 0 || optInEnd <= optInAt ? '' : failureBranch.slice(optInAt, optInEnd);
  if ((optInBranch.match(/classifyInactiveWaitFailure\(output, expected\)/g) ?? []).length !== 1 ||
      (optInBranch.match(/classifyOptInTestFailureSites\(output, expected\)/g) ?? []).length !== 1 ||
      !optInBranch.includes('process.stderr.write(`bounded WSL test oracle exited ${result.status ?? \'without a status\'}; ${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\\n`);') ||
      optInBranch.includes('process.stderr.write(output)') || optInBranch.includes('process.stderr.write(`${output') ||
      !optInBranch.includes('preservePrivateWorkspace = true')) throw new Error('opt-in failure branch must consume both bounded reducers once and emit only their fixed summaries');
  return true;
}

function sourceLineForReviewedTest(testName, sourceFiles) {
  for (const [relative, details] of sourceFiles) {
    const marker = `func ${testName}(`;
    const at = details.source.indexOf(marker);
    if (at >= 0) return { relative, line: details.source.slice(0, at).split(/\r?\n/).length };
  }
  throw new Error(`reviewed test source is missing: ${testName}`);
}

function selfTestOptInTestFailureSites(source) {
  validateOptInTestFailureSiteSource(source);
  const sourceFiles = loadDiagnosticTestSources();
  const owner = 'TestCheckpointPlanRelaunchCPULifecycleSequence';
  const otherOwner = 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect';
  const successOwner = 'TestCheckpointPlanCatalogRequiresCanonicalApprovedV2Bytes';
  const firstSite = sourceLineForReviewedTest(owner, sourceFiles);
  const secondSite = sourceLineForReviewedTest(otherOwner, sourceFiles);
  const passSite = sourceLineForReviewedTest(successOwner, sourceFiles);
  const firstBase = path.posix.basename(firstSite.relative);
  const secondBase = path.posix.basename(secondSite.relative);
  const successBase = path.posix.basename(passSite.relative);
  const oneFailure = `=== RUN   ${owner}\n    /private/worktree/${firstSite.relative}:${firstSite.line}: private assertion text TOKEN-ONE\n--- FAIL: ${owner} (0.10s)\n`;
  const oneResult = classifyOptInTestFailureSites(oneFailure, [owner]);
  if (oneResult !== `test_sites=${owner}=${firstBase}:${firstSite.line}` || /TOKEN|private|worktree|assertion/.test(oneResult)) throw new Error('single failure source-site positive did not produce only fixed owner and basename/line');

  const twoFailuresAndPass = `=== RUN   ${successOwner}\n    ${passSite.relative}:${passSite.line}: private passing detail\n--- PASS: ${successOwner} (0.01s)\n` +
    `=== RUN   ${owner}\n    ${firstSite.relative}:${firstSite.line}: private first failure\n--- FAIL: ${owner} (0.10s)\n` +
    `=== RUN   ${otherOwner}\n    ${secondSite.relative}:${secondSite.line}: private second failure\n--- FAIL: ${otherOwner} (0.20s)\n`;
  const twoResult = classifyOptInTestFailureSites(twoFailuresAndPass, [owner, otherOwner, successOwner]);
  if (twoResult !== `test_sites=${owner}=${firstBase}:${firstSite.line};${otherOwner}=${secondBase}:${secondSite.line}` || /private|worktree|failure/.test(twoResult)) throw new Error('two-owner diagnostic did not retain actual failed-test order or suppress private text');

  const nestedFailure = `=== RUN   ${owner}\n=== RUN   ${owner}/nested_case\n    ${firstSite.relative}:${firstSite.line}: nested assertion\n--- FAIL: ${owner}/nested_case (0.01s)\n--- FAIL: ${owner} (0.10s)\n`;
  if (classifyOptInTestFailureSites(nestedFailure, [owner]) !== `test_sites=${owner}=${firstBase}:${firstSite.line}`) throw new Error('nested failed subtest was not attributed to its exact selected top-level owner');

  const invalid = [
    ['unselected expected owner', oneFailure, ['TestUnselectedOwner']],
    ['missing owner RUN', oneFailure.replace(`=== RUN   ${owner}\n`, ''), [owner]],
    ['duplicate owner RUN', oneFailure.replace(`=== RUN   ${owner}\n`, `=== RUN   ${owner}\n=== RUN   ${owner}\n`), [owner]],
    ['missing owner FAIL', oneFailure.replace(`--- FAIL: ${owner}`, `--- PASS: ${owner}`), [owner]],
    ['duplicate owner FAIL', oneFailure.replace(`--- FAIL: ${owner} (0.10s)\n`, `--- FAIL: ${owner} (0.10s)\n--- FAIL: ${owner} (0.10s)\n`), [owner]],
    ['contradictory owner FAIL then PASS', oneFailure.replace(`--- FAIL: ${owner} (0.10s)`, `--- FAIL: ${owner} (0.10s)\n--- PASS: ${owner} (0.10s)`), [owner]],
    ['missing site', oneFailure.replace(`    /private/worktree/${firstSite.relative}:${firstSite.line}: private assertion text TOKEN-ONE\n`, ''), [owner]],
    ['duplicate canonical site', oneFailure.replace(`    /private/worktree/${firstSite.relative}:${firstSite.line}: private assertion text TOKEN-ONE\n`,
      `    /private/worktree/${firstSite.relative}:${firstSite.line}: first private detail\n    ${firstSite.relative}:${firstSite.line}: duplicate private detail\n`), [owner]],
    ['valid site mixed with unknown source token', oneFailure.replace(`private assertion text TOKEN-ONE`, `private detail ${path.posix.basename(firstSite.relative).replace('_test.go', '_unknown_test.go')}:2: hidden`), [owner]],
    ['valid site mixed with malformed source token', oneFailure.replace(`private assertion text TOKEN-ONE`, 'private detail malformed_test.go:+2: hidden'), [owner]],
    ['valid site mixed with non-test source token', oneFailure.replace(`private assertion text TOKEN-ONE`, 'private detail checkpoint_lifecycle_broker.go:22: hidden'), [owner]],
    ['site outside owner interval', oneFailure.replace(`    /private/worktree/${firstSite.relative}:${firstSite.line}: private assertion text TOKEN-ONE\n`, '').replace(`=== RUN   ${owner}\n`, `    ${firstSite.relative}:${firstSite.line}: private assertion text TOKEN-ONE\n=== RUN   ${owner}\n`), [owner]],
    ['contradictory PASS/SKIP', oneFailure.replace(`--- FAIL: ${owner}`, `--- SKIP: ${owner}`), [owner]],
    ['intervening other-test event', oneFailure.replace(`    /private/worktree/${firstSite.relative}:${firstSite.line}:`, `=== RUN   TestForeignSelected\n    /private/worktree/${firstSite.relative}:${firstSite.line}:`), [owner]],
    ['malformed lifecycle', oneFailure.replace(`=== RUN   ${owner}`, `=== NAME  ${owner}`), [owner]],
    ['non-test Go source site', oneFailure.replace(firstBase, 'checkpoint_lifecycle_broker.go'), [owner]],
    ['contradictory nested failure and parent PASS', `=== RUN   ${owner}\n=== RUN   ${owner}/sub\n    ${firstSite.relative}:${firstSite.line}: nested detail\n--- FAIL: ${owner}/sub (0.01s)\n--- PASS: ${owner} (0.10s)\n` +
      `=== RUN   ${otherOwner}\n    ${secondSite.relative}:${secondSite.line}: second owner detail\n--- FAIL: ${otherOwner} (0.20s)\n`, [owner, otherOwner]],
    ['unknown source basename', oneFailure.replace(firstBase, 'unreviewed_test.go'), [owner]],
    ['leading-zero source line', oneFailure.replace(`:${firstSite.line}:`, `:0${firstSite.line}:`), [owner]],
    ['signed source line', oneFailure.replace(`:${firstSite.line}:`, `:+${firstSite.line}:`), [owner]],
    ['out-of-range source line', oneFailure.replace(`:${firstSite.line}:`, `:${sourceFiles.get(firstSite.relative).lineCount + 1}:`), [owner]],
    ['too many distinct sites', `=== RUN   ${owner}\n${[0, 1, 2, 3, 4].map((n) => `    ${firstSite.relative}:${firstSite.line + n}: detail\n`).join('')}--- FAIL: ${owner} (0.10s)\n`, [owner]],
    ['oversize capture', `${oneFailure}${'x'.repeat(maxFailureCaptureBytes)}`, [owner]],
    ['oversize line', `=== RUN   ${owner}\n${' '.repeat(maxFailureLineBytes)}\n--- FAIL: ${owner} (0.10s)\n`, [owner]],
  ];
  for (const [label, output, expected] of invalid) {
    if (classifyOptInTestFailureSites(output, expected) !== 'test_sites=unavailable') throw new Error(`failure-site reducer accepted ${label}`);
  }

  const duplicateGuardNeedle = 'if (siteSet.has(siteKey)) return unavailable;';
  const duplicateGuardMutant = source.replace(duplicateGuardNeedle, 'if (false) return unavailable;');
  if (duplicateGuardMutant === source) throw new Error('duplicate-site guard source mutant anchor is absent');
  let duplicateGuardRejected = false;
  try { validateOptInTestFailureSiteSource(duplicateGuardMutant); } catch { duplicateGuardRejected = true; }
  if (!duplicateGuardRejected) throw new Error('failure-site source controls accepted a removed duplicate-site guard');

  const mixedGuardNeedle = 'if (goTokenCount !== matches.length) return unavailable;';
  const mixedGuardMutant = source.replace(mixedGuardNeedle, 'if (false) return unavailable;');
  if (mixedGuardMutant === source) throw new Error('mixed-source-token guard source mutant anchor is absent');
  let mixedGuardRejected = false;
  try { validateOptInTestFailureSiteSource(mixedGuardMutant); } catch { mixedGuardRejected = true; }
  if (!mixedGuardRejected) throw new Error('failure-site source controls accepted a removed mixed-source-token guard');

  const bypassNeedle = "      const diagnostic = classifyInactiveWaitFailure(output, expected);\n      const siteDiagnostic = classifyOptInTestFailureSites(output, expected);";
  const bypass = source.replace(bypassNeedle, "      const diagnostic = classifyInactiveWaitFailure(output, expected);\n      const siteDiagnostic = 'test_sites=unavailable';");
  if (bypass === source) throw new Error('failure-site reducer consumption mutant anchor is absent');
  let bypassRejected = false;
  try { validateOptInTestFailureSiteSource(bypass); } catch { bypassRejected = true; }
  if (!bypassRejected) throw new Error('failure-site source controls accepted a bypassed diagnostic reducer');
  const rawOutputNeedle = "      const stageDiagnostic = classifyTypedFailureStage(output, expected);\n      process.stderr.write(`bounded WSL test oracle exited ${result.status ?? 'without a status'}; ${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\\n`);";
  const rawOutput = source.replace(rawOutputNeedle, "      const stageDiagnostic = classifyTypedFailureStage(output, expected);\n      process.stderr.write(output);");
  if (rawOutput === source) throw new Error('raw failure output privacy mutant anchor is absent');
  let rawRejected = false;
  try { validateOptInTestFailureSiteSource(rawOutput); } catch { rawRejected = true; }
  if (!rawRejected) throw new Error('failure-site source controls accepted raw output forwarding');
  return true;
}

function validateGuardDescriptorDiagnosticSource(source) {
  const python = uniqueSourceRegion(source, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())');
  const predicate = uniqueSourceRegion(python, 'def validate_guard_duplicate(expected):', '\nclass LinuxDirent64');
  const direntClass = uniqueSourceRegion(python, 'class LinuxDirent64(ctypes.Structure):', '\ndef descriptor_identity');
  const scan = uniqueSourceRegion(python, 'def scan_guard_writer_provenance():', '\ndef native_state():');
  const enumeration = uniqueSourceRegion(scan, '        def enumerate_pass(name_budget):', '        def observe_fd(');
  const observation = uniqueSourceRegion(scan, '        def observe_fd(fd,expected_guard):', '        before_scanner=scanner_snapshot()');
  const fail = (message) => { throw new Error(`guard descriptor diagnostic source predicate: ${message}`); };
  const mainAt = python.indexOf('\ndef main():');
  const nextFunctionPattern = /\ndef [A-Za-z_][A-Za-z0-9_]*\(/g;
  if (mainAt >= 0) nextFunctionPattern.lastIndex = mainAt + 1;
  const nextTopLevelFunction = mainAt < 0 ? '' : nextFunctionPattern.exec(python)?.[0] ?? '';
  if (mainAt < 0 || nextTopLevelFunction !== '\ndef descriptor_control_main(') fail('exact main region must end at its immediate descriptor-control declaration');
  const main = uniqueSourceRegion(python, 'def main():', 'def descriptor_control_main(name):');
  if (!predicate.includes('except OSError as e:\n        if e.errno!=9:\n            die(149)\n        if expected:\n            die(150)\n        duplicate=None\n        initial=None')) fail('expected=true absent fd10 rejection and false absent scan setup must remain exact');
  if (!predicate.includes('observations,guard,scanner_number=scan_guard_writer_provenance()') ||
      !predicate.includes('duplicate_observation=observations.get(DUP_GUARD)') ||
      !predicate.includes('duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY') ||
      !predicate.includes('if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):\n                die(178)') ||
      !predicate.includes('if duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)') ||
      !predicate.includes('if scanner_number!=DUP_GUARD and DUP_GUARD in observations:\n                die(194)') ||
      !predicate.includes('if any(observation[3] for observation in observations.values()):\n            die(195)') ||
      !predicate.includes('except Exception:\n        die(194)')) fail('object-based expected and absent/present false branches must scan and retain finite fail-closed outcomes');
  if (!python.includes('HISTORICAL_UNRELATED_FD10_EXIT=193') || !source.includes('Historical Broker55 diagnostic exit only; live object validation no longer exits on unrelated fd10.')) fail('historical Broker55 finite outcome must be explicitly non-live');
  const controlDuplicateAt = main.indexOf("validate_guard_duplicate(control_case=='parentdeath_after_rearm')");
  const normalDuplicateAt = main.indexOf('validate_guard_duplicate(False)');
  const tokenAt = main.indexOf('token=os.read(GUARD,1)');
  const readyAt = main.indexOf("emit('GUARD_READY')");
  if (controlDuplicateAt < 0 || normalDuplicateAt < 0 ||
      (main.match(/validate_guard_duplicate\(/g) ?? []).length !== 2 ||
      !main.includes("            else: die(131)\n            validate_guard_duplicate(control_case=='parentdeath_after_rearm')\n") ||
      !main.includes("            except OSError as block_error:\n                if block_error.errno!=9: raise\n            validate_guard_duplicate(False)\n        token=os.read(GUARD,1)") ||
      controlDuplicateAt >= normalDuplicateAt || controlDuplicateAt >= tokenAt || normalDuplicateAt >= tokenAt || tokenAt < 0 || tokenAt >= readyAt || readyAt < 0) fail('diagnostic predicate must stay at both original pre-token, pre-GUARD_READY call sites');

  for (const [required, label] of [
    ["sys.platform!='linux'", 'supported Linux ABI guard'],
    ['ctypes.sizeof(ctypes.c_void_p)!=8', '64-bit pointer ABI guard'],
    ['ctypes.sizeof(ctypes.c_ulong)!=8', '64-bit inode field ABI guard'],
    ['ctypes.sizeof(ctypes.c_long)!=8', '64-bit dirent field ABI guard'],
    ['ctypes.sizeof(LinuxDirent64)!=280', 'explicit Linux dirent record layout'],
    ['LinuxDirent64.d_name.offset!=19', 'explicit Linux dirent name offset'],
    ['libc.fdopendir.argtypes=[ctypes.c_int]', 'typed fdopendir signature'],
    ['libc.fdopendir.restype=ctypes.c_void_p', 'typed fdopendir result'],
    ['libc.readdir.argtypes=[ctypes.c_void_p]', 'typed readdir signature'],
    ['libc.readdir.restype=ctypes.POINTER(LinuxDirent64)', 'typed readdir record result'],
    ['libc.rewinddir.argtypes=[ctypes.c_void_p]', 'typed rewinddir signature'],
    ['libc.rewinddir.restype=None', 'typed rewinddir result'],
    ['libc.closedir.argtypes=[ctypes.c_void_p]', 'typed closedir signature'],
    ['libc.closedir.restype=ctypes.c_int', 'typed closedir result'],
    ['libc.dirfd.argtypes=[ctypes.c_void_p]', 'typed scanner descriptor lookup'],
    ['libc.dirfd.restype=ctypes.c_int', 'typed scanner descriptor result'],
    ["os.open('/proc/self/fd',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)", 'fixed owned scanner open'],
    ['stream=libc.fdopendir(scanner_fd)', 'owned scanner transfer to fdopendir'],
    ['scanner_fd=-1', 'single fdopendir ownership transfer'],
    ['deadline=time.monotonic_ns()+100000000', 'hard 100ms observation deadline'],
    ['if time.monotonic_ns()>=deadline:', 'deadline enforcement'],
    ["if time.monotonic_ns()>=deadline:\n            raise RuntimeError('descriptor observation deadline')", 'deadline includes scanner cleanup'],
    ['while True:\n                check_deadline()\n                ctypes.set_errno(0)\n                entry=libc.readdir(stream)', 'complete readdir loop on held stream'],
    ['if not entry:\n                    if ctypes.get_errno()!=0:\n                        raise OSError(ctypes.get_errno(),\'readdir failed\')\n                    break', 'EOF is accepted only after a complete error-free directory pass'],
    ['if ctypes.get_errno()!=0:\n                        raise OSError(ctypes.get_errno(),\'readdir failed\')', 'enumeration error detection'],
    ['record_length<LinuxDirent64.d_name.offset+1 or record_length>ctypes.sizeof(LinuxDirent64)', 'bounded dirent record validation'],
    ['raw=ctypes.string_at(ctypes.addressof(record)+LinuxDirent64.d_name.offset,record_length-LinuxDirent64.d_name.offset)', 'bounded dirent record memory read'],
    ['terminator=raw.find(b\'\\0\')', 'NUL-terminated dirent name validation'],
    ['record_length!=((LinuxDirent64.d_name.offset+terminator+1+7)//8)*8', 'Linux dirent name and aligned record-length consistency'],
    ['if not raw_name or raw_name in seen:', 'duplicate and empty directory name rejection'],
    ['seen.add(raw_name)', 'directory entry uniqueness tracking'],
    ['raw_name.isdigit()', 'canonical numeric descriptor recognition'],
    ['str(number).encode(\'ascii\')!=raw_name', 'canonical numeric descriptor spelling'],
    ['if raw_name not in (b\'.\',b\'..\')', 'reject malformed nonnumeric proc entries'],
    ['if len(numeric)>=128:', 'fail-closed 128 descriptor cap'],
    ['total+=len(raw_name)', 'total directory name byte accounting'],
    ['if total>=8192:', 'fail-closed 8192 name byte cap'],
    ['if scanner_number not in numeric:', 'held scanner is the only excluded entry'],
    ['first_names,used_names=enumerate_pass(0)', 'first complete descriptor pass'],
    ['libc.rewinddir(stream)', 'same held scanner rewind'],
    ['second_names,used_names=enumerate_pass(used_names)', 'second complete descriptor pass'],
    ['return second,guard,scanner_number', 'scanner identity returned for fd10 race accounting'],
    ['second_names!=first_names', 'complete pass entry set currentness'],
    ['second!=first', 'descriptor identity and flags currentness across passes'],
    ['scanner_snapshot()!=before_scanner', 'owned scanner identity currentness'],
    ['guard_snapshot()!=guard', 'guard identity and flags currentness'],
    ['guard_before=guard_snapshot()', 'fresh guard identity before classification'],
    ['guard_after=guard_snapshot()', 'fresh guard identity after classification'],
    ['guard_after!=expected_guard', 'guard stable throughout descriptor classification'],
    ['before_info=os.fstat(fd)', 'fstat each observed descriptor before classification'],
    ['before_flags=fcntl.fcntl(fd,fcntl.F_GETFL)', 'F_GETFL each observed descriptor before classification'],
    ['after_flags=fcntl.fcntl(fd,fcntl.F_GETFL)', 'F_GETFL each observed descriptor after classification'],
    ['after_info=os.fstat(fd)', 'fstat each observed descriptor after classification'],
    ['descriptor_identity(after_info)!=identity or after_flags!=before_flags', 'per-descriptor identity and flags stability'],
    ['stat.S_ISFIFO(before_info.st_mode) and identity[0]==expected_guard[0][0] and identity[1]==expected_guard[0][1]', 'same-pipe proof requires FIFO device and inode equality'],
    ['before_flags&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR)', 'guard writer proof requires write access mode'],
    ['first={fd:observe_fd(fd,guard) for fd in first_names if fd!=scanner_number}', 'classify every first-pass descriptor except only held scanner'],
    ['second={fd:observe_fd(fd,guard) for fd in second_names if fd!=scanner_number}', 'classify every second-pass descriptor except only held scanner'],
    ['libc.closedir(stream)', 'close exactly the owned stream'],
    ['elif scanner_fd>=0:\n            os.close(scanner_fd)', 'close original owned fd exactly once if fdopendir fails'],
    ['if close_result!=0:\n                raise OSError(ctypes.get_errno(),\'closedir failed\')', 'closedir failure is uncertainty'],
  ]) if (!scan.includes(required) && !enumeration.includes(required) && !observation.includes(required)) fail(label);
  for (const [region, requirements] of [
    [enumeration, [
      ['while True:\n                check_deadline()\n                ctypes.set_errno(0)\n                entry=libc.readdir(stream)', 'complete readdir loop on held stream'],
      ['record_length<LinuxDirent64.d_name.offset+1 or record_length>ctypes.sizeof(LinuxDirent64)', 'bounded dirent record validation'],
      ['raw=ctypes.string_at(ctypes.addressof(record)+LinuxDirent64.d_name.offset,record_length-LinuxDirent64.d_name.offset)', 'bounded dirent record memory read'],
      ["terminator=raw.find(b'\\0')", 'NUL-terminated dirent name validation'],
      ['if len(numeric)>=128:', 'fail-closed 128 descriptor cap'],
      ['if total>=8192:', 'fail-closed 8192 name byte cap'],
      ['if scanner_number not in numeric:', 'held scanner is the only excluded entry'],
    ]],
    [observation, [
      ['guard_before=guard_snapshot()', 'fresh guard identity before classification'],
      ['guard_after=guard_snapshot()', 'fresh guard identity after classification'],
      ['before_info=os.fstat(fd)', 'fstat each observed descriptor before classification'],
      ['before_flags=fcntl.fcntl(fd,fcntl.F_GETFL)', 'F_GETFL each observed descriptor before classification'],
      ['after_flags=fcntl.fcntl(fd,fcntl.F_GETFL)', 'F_GETFL each observed descriptor after classification'],
      ['after_info=os.fstat(fd)', 'fstat each observed descriptor after classification'],
      ['descriptor_identity(after_info)!=identity or after_flags!=before_flags', 'per-descriptor identity and flags stability'],
      ['stat.S_ISFIFO(before_info.st_mode) and identity[0]==expected_guard[0][0] and identity[1]==expected_guard[0][1]', 'same-pipe proof requires FIFO device and inode equality'],
      ['before_flags&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR)', 'guard writer proof requires write access mode'],
    ]],
  ]) for (const [required, label] of requirements) if (!region.includes(required)) fail(`${label} must remain in its owning source region`);
  if (!direntClass.includes("_fields_=[('d_ino',ctypes.c_ulong),('d_off',ctypes.c_long),('d_reclen',ctypes.c_ushort),('d_type',ctypes.c_ubyte),('d_name',ctypes.c_char*256)]")) fail('explicit Linux dirent field ABI');
  const scannerOpen = scan.indexOf("scanner_fd=os.open('/proc/self/fd',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)");
  const fdopendirAt = scan.indexOf('stream=libc.fdopendir(scanner_fd)');
  const fdopendirFailureAt = scan.indexOf('if not stream:', fdopendirAt);
  const transferAt = scan.indexOf('scanner_fd=-1', fdopendirAt);
  const scannerLookupAt = scan.indexOf('scanner_number=libc.dirfd(stream)');
  const firstPassAt = scan.indexOf('first_names,used_names=enumerate_pass(0)');
  const rewindAt = scan.indexOf('libc.rewinddir(stream)');
  const secondPassAt = scan.indexOf('second_names,used_names=enumerate_pass(used_names)');
  const streamCloseAt = scan.indexOf('libc.closedir(stream)');
  const fdCloseAt = scan.indexOf('os.close(scanner_fd)');
  if (!(scannerOpen >= 0 && fdopendirAt > scannerOpen && fdopendirFailureAt > fdopendirAt && transferAt > fdopendirFailureAt && scannerLookupAt > transferAt &&
      firstPassAt > scannerLookupAt && rewindAt > firstPassAt && secondPassAt > rewindAt && streamCloseAt > secondPassAt && fdCloseAt > streamCloseAt)) {
    fail('scanner open, fdopendir transfer, two-pass custody and exactly-once owned close order');
  }
  if ((scan.match(/os\.open\(/g) ?? []).length !== 1 || (scan.match(/os\.close\(/g) ?? []).length !== 1 ||
      !scan.includes('os.close(scanner_fd)') || scan.includes('os.close(fd)') || scan.includes('os.close(DUP_GUARD)') ||
      (scan.match(/libc\.closedir\(stream\)/g) ?? []).length !== 1 || scan.includes('os.listdir(') || scan.includes('os.scandir(') ||
      scan.includes('readlink') || scan.includes('subprocess') || scan.includes('Popen(') || scan.includes('systemctl') ||
      scan.includes('signal.setitimer(') || predicate.includes('signal.setitimer(') ||
      scan.includes('emit(') || scan.includes('report(') || scan.includes('print(') || predicate.includes('emit(') || predicate.includes('report(') || predicate.includes('print(') ||
      JSON.stringify(scan.match(/'\/[^']+'/g) ?? []) !== JSON.stringify(["'/proc/self/fd'"])) fail('scanner ownership, fixed path, no-unknown-close, no-output and original timer constraints');
  if ((predicate.match(/die\(151\)/g) ?? []).length !== 1 || (predicate.match(/die\(152\)/g) ?? []).length !== 2 ||
      (predicate.match(/die\(178\)/g) ?? []).length !== 1 || (predicate.match(/die\(194\)/g) ?? []).length !== 7 ||
      (predicate.match(/die\(195\)/g) ?? []).length !== 1) fail('exact finite diagnostic exit meanings');
  return true;
}

function selfTestGuardDescriptorDiagnosticSource(source) {
  validateGuardDescriptorDiagnosticSource(source);
  const mutate = (needle, replacement, label, intended) => {
    if (source.split(needle).length !== 2) throw new Error(`guard descriptor source mutant anchor is not unique: ${label}`);
    const mutant = source.replace(needle, replacement);
    let reason = '';
    try { validateGuardDescriptorDiagnosticSource(mutant); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`guard descriptor diagnostic source predicate: ${intended}`)) throw new Error(`guard descriptor controls missed ${label} mutant's intended predicate: ${reason || 'accepted'}`);
  };
  mutate("            validate_guard_duplicate(control_case=='parentdeath_after_rearm')\n", '            pass\n', 'omitted control duplicate call', 'diagnostic predicate must stay at both original pre-token, pre-GUARD_READY call sites');
  mutate("            validate_guard_duplicate(False)\n        token=os.read(GUARD,1)", "        token=os.read(GUARD,1)\n        validate_guard_duplicate(False)", 'moved normal duplicate call after token', 'diagnostic predicate must stay at both original pre-token, pre-GUARD_READY call sites');
  mutate("            validate_guard_duplicate(False)\n        token=os.read(GUARD,1)", "            validate_guard_duplicate(False)\n            validate_guard_duplicate(False)\n        token=os.read(GUARD,1)", 'extra original-main duplicate call', 'diagnostic predicate must stay at both original pre-token, pre-GUARD_READY call sites');
  const descriptorCallAnchor = '    validate_guard_duplicate(expected)\n    token=(\'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__';
  if (source.split(descriptorCallAnchor).length !== 2) throw new Error('guard descriptor boundary control anchor is not unique');
  const descriptorCallBoundaryControl = source.replace(
    descriptorCallAnchor,
    '    validate_guard_duplicate(expected)\n    validate_guard_duplicate(False)\n    token=(\'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__',
  );
  if (descriptorCallBoundaryControl === source) throw new Error('guard descriptor boundary control anchor is missing');
  validateGuardDescriptorDiagnosticSource(descriptorCallBoundaryControl);
  mutate('\n\ndef descriptor_control_main(name):\n    cases={', '\n\ndef descriptor_control_main_moved(name):\n    cases={', 'missing immediate descriptor-control boundary', 'exact main region must end at its immediate descriptor-control declaration');
  mutate('ctypes.addressof(record)+LinuxDirent64.d_name.offset', 'ctypes.addressof(record.contents)+LinuxDirent64.d_name.offset', 'bad double dereference', 'bounded dirent record memory read');
  mutate("_fields_=[('d_ino',ctypes.c_ulong),('d_off',ctypes.c_long),('d_reclen',ctypes.c_ushort),('d_type',ctypes.c_ubyte),('d_name',ctypes.c_char*256)]", "_fields_=[('d_ino',ctypes.c_uint64),('d_off',ctypes.c_long),('d_reclen',ctypes.c_ushort),('d_type',ctypes.c_ubyte),('d_name',ctypes.c_char*256)]", 'dirent class layout in its owning region', 'explicit Linux dirent field ABI');
  mutate('stat.S_ISFIFO(before_info.st_mode) and identity[0]==expected_guard[0][0] and identity[1]==expected_guard[0][1]', 'False', 'numeric-only guard proof', 'same-pipe proof requires FIFO device and inode equality');
  mutate('while True:\n                check_deadline()\n                ctypes.set_errno(0)\n                entry=libc.readdir(stream)', 'for _ in range(7):\n                check_deadline()\n                ctypes.set_errno(0)\n                entry=libc.readdir(stream)', 'fixed-range truncated scan', 'complete readdir loop on held stream');
  mutate('if ctypes.get_errno()!=0:\n                        raise OSError(ctypes.get_errno(),\'readdir failed\')', 'if False:\n                        raise OSError(ctypes.get_errno(),\'readdir failed\')', 'truncated readdir treated as a complete scan', 'EOF is accepted only after a complete error-free directory pass');
  mutate('second_names,used_names=enumerate_pass(used_names)', 'second_names,used_names=first_names,used_names', 'missing second descriptor pass', 'second complete descriptor pass');
  mutate('second!=first', 'False', 'missing descriptor currentness comparison', 'descriptor identity and flags currentness across passes');
  mutate('before_info=os.fstat(fd)', 'before_info=os.fstat(GUARD)', 'ignored disappearing descriptor', 'fstat each observed descriptor before classification');
  mutate('before_flags&os.O_ACCMODE in (os.O_WRONLY,os.O_RDWR)', 'before_flags&os.O_ACCMODE in (os.O_RDONLY,)', 'wrong read/write classification', 'guard writer proof requires write access mode');
  mutate('os.close(scanner_fd)', 'os.close(DUP_GUARD)', 'close unknown descriptor', 'close original owned fd exactly once if fdopendir fails');
  mutate('        if duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)', '        if False and duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)', 'false fd10 writer accepted', 'object-based expected and absent/present false branches must scan and retain finite fail-closed outcomes');
  mutate('        if any(observation[3] for observation in observations.values()):\n            die(195)', '        if False and any(observation[3] for observation in observations.values()):\n            die(195)', 'false higher writer accepted', 'object-based expected and absent/present false branches must scan and retain finite fail-closed outcomes');
  mutate('            if duplicate_observation is None or duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY:', '            if False:', 'true unrelated descriptor accepted', 'object-based expected and absent/present false branches must scan and retain finite fail-closed outcomes');
  mutate('            if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):', '            if False:', 'true extra writer accepted', 'object-based expected and absent/present false branches must scan and retain finite fail-closed outcomes');
  mutate('deadline=time.monotonic_ns()+100000000', 'deadline=time.monotonic_ns()+100000001', 'expanded observation timer', 'hard 100ms observation deadline');
  mutate('if len(numeric)>=128:', 'if len(numeric)>128:', 'accept descriptor cap boundary', 'fail-closed 128 descriptor cap');
  mutate('if total>=8192:', 'if total>8192:', 'accept name byte cap boundary', 'fail-closed 8192 name byte cap');
  return true;
}

function validateDescriptorGuardControlSource(source) {
  const fail = (message) => { throw new Error(`descriptor guard control source predicate: ${message}`); };
  const python = uniqueSourceRegion(source, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())');
  const goTest = uniqueSourceRegion(source, 'const planBrokerCPUDescriptorGuardControlAssertion =', '\ntype planBrokerCPUPreReadyWriteFunc');
  const names = [
    'false_absent_no_writer', 'false_unrelated_no_writer', 'true_exact_fd10_writer',
    'false_fd10_writer', 'false_unrelated_higher_writer', 'false_absent_higher_writer',
    'true_missing_fd10', 'true_unrelated_fd10', 'true_exact_plus_extra_writer',
  ];
  const pyCases = [...python.matchAll(/^        '([a-z0-9_]+)':\((True|False),(True|False)\),?$/gm)].map((match) => match[1]);
  const goCases = [...goTest.matchAll(/name: "([a-z0-9_]+)"/g)].map((match) => match[1]);
  const goEvents = [...goTest.matchAll(/\{name: "([a-z0-9_]+)", expected: (\d+),/g)].map((match) => [match[1], Number(match[2])]);
  if (JSON.stringify(pyCases) !== JSON.stringify(names) || JSON.stringify(goCases) !== JSON.stringify(names)) fail('the nine actual descriptor cases must be closed, unique and positive-first in both languages');
  if (JSON.stringify(goEvents) !== JSON.stringify(descriptorGuardControlCases)) fail('Go terminal exit matrix must match the production result classifier exact-once and in order');
  const mutantBindings = [
    ['func TestPlanBrokerCPUDescriptorGuardMutantFD10(t *testing.T) {', '\nfunc TestPlanBrokerCPUDescriptorGuardMutantHigher(t *testing.T) {', 'false_fd10_writer'],
    ['func TestPlanBrokerCPUDescriptorGuardMutantHigher(t *testing.T) {', '\nfunc TestPlanBrokerCPUDescriptorGuardMutantWrongFD10(t *testing.T) {', 'false_unrelated_higher_writer'],
    ['func TestPlanBrokerCPUDescriptorGuardMutantWrongFD10(t *testing.T) {', '\nfunc TestPlanBrokerCPUDescriptorGuardMutantExtraWriter(t *testing.T) {', 'true_unrelated_fd10'],
    ['func TestPlanBrokerCPUDescriptorGuardMutantExtraWriter(t *testing.T) {', '\ntype planBrokerCPUPreReadyWriteFunc', 'true_exact_plus_extra_writer'],
  ];
  for (const [start, end, name] of mutantBindings) {
    const test = uniqueSourceRegion(source, start, end);
    const calls = [...test.matchAll(/assertPlanBrokerCPUDescriptorGuardMutantDetected\(t, "([a-z0-9_]+)"\)/g)].map((match) => match[1]);
    if (JSON.stringify(calls) !== JSON.stringify([name])) fail(`compiled mutant test ${start} must target only its decisive case ${name}`);
  }
  for (const required of [
    "'false_absent_no_writer':(False,True)", "'false_unrelated_no_writer':(False,False)",
    "'true_exact_fd10_writer':(True,False)", "'false_fd10_writer':(False,False)",
    "'false_unrelated_higher_writer':(False,False)", "'false_absent_higher_writer':(False,True)",
    "'true_missing_fd10':(True,True)", "'true_unrelated_fd10':(True,False)",
    "'true_exact_plus_extra_writer':(True,False)",
  ]) if (!python.includes(required)) fail(`Python descriptor setup does not encode ${required}`);
  for (const required of [
    '{name: "false_absent_no_writer", expected: 0, fd10: "unrelated"}',
    '{name: "false_unrelated_no_writer", expected: 0, fd10: "unrelated"}',
    '{name: "true_exact_fd10_writer", expected: 0, fd10: "guard_writer"}',
    '{name: "false_fd10_writer", expected: 151, fd10: "guard_writer"}',
    '{name: "false_unrelated_higher_writer", expected: 195, fd10: "unrelated", highWriter: true}',
    '{name: "false_absent_higher_writer", expected: 195, fd10: "unrelated", highWriter: true}',
    '{name: "true_missing_fd10", expected: 150, fd10: "unrelated"}',
    '{name: "true_unrelated_fd10", expected: 152, fd10: "unrelated"}',
    '{name: "true_exact_plus_extra_writer", expected: 178, fd10: "guard_writer", highWriter: true}',
  ]) if (!goTest.includes(required)) fail(`Go descriptor control does not encode ${required}`);
  for (const required of [
    'descriptor_control_main(sys.argv[1].split(\'=\',1)[1])', 'validate_guard_duplicate(expected)',
    "os.write(1,token)", 'os._exit(0)',
    "token=('__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\\t'+name+'\\t0\\n').encode('ascii','strict')",
  ]) if (!python.includes(required)) fail(`embedded Python control does not use the actual predicate and exact result token: ${required}`);
  for (const required of [
    'command.ExtraFiles = extra', '"/usr/bin/python3", "-I", "-c", planBrokerCPUUnitHolderProgram',
    'for len(extra) < 7', 'if test.fd10 == "guard_writer"', 'if test.highWriter',
    'context.WithTimeout(context.Background(), 2*time.Second)', 'command.WaitDelay = 250*time.Millisecond',
    'command.ProcessState == nil || !command.ProcessState.Exited()', 'stdout.over || stderr.over',
    'test.expected == 0', 'outcome.stdout != want', 'outcome.stderr != ""',
    'expected: 151', 'expected: 195', 'expected: 150', 'expected: 152', 'expected: 178',
    'fmt.Printf("%s%s\\t%d\\n", planBrokerCPUDescriptorGuardPassPrefix, test.name, test.expected)',
    'func TestPlanBrokerCPUDescriptorGuardMutantFD10(t *testing.T)',
    'func TestPlanBrokerCPUDescriptorGuardMutantHigher(t *testing.T)',
    'func TestPlanBrokerCPUDescriptorGuardMutantWrongFD10(t *testing.T)',
    'func TestPlanBrokerCPUDescriptorGuardMutantExtraWriter(t *testing.T)',
    'if outcome.exitCode == test.expected && outcome.stdout == "" && outcome.stderr == "" { return }',
    'if outcome.exitCode == 0 && outcome.stdout == want && outcome.stderr == "" {',
    't.Fatalf("%s\\tcase=%s: forbidden descriptor acceptance observed", planBrokerCPUDescriptorGuardControlAssertion, name)',
    'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_fd10_writer")',
    'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_unrelated_higher_writer")',
    'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_unrelated_fd10")',
    'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_exact_plus_extra_writer")',
  ]) if (!goTest.includes(required)) fail(`Go actual descriptor control is missing ${required}`);
  if (!goTest.includes('func TestPlanBrokerCPUDescriptorGuardControls(t *testing.T)') ||
      !goTest.includes('func runPlanBrokerCPUDescriptorGuardCase(') || goTest.includes('t.Run(') ||
      !goTest.includes('func (writer *planBrokerCPUDescriptorGuardBoundedOutput) Write(data []byte)') ||
      !goTest.includes('const planBrokerCPUDescriptorGuardPassPrefix = "__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\\t"')) fail('nine-case test must be sequential, terminally bounded, and emit explicit per-case completion evidence without subtests');
  return true;
}

function validatePrivateDescriptorSelectorSuffix(source, python) {
  const fail = (message) => { throw new Error(`fixed helper descriptor suffix predicate: ${message}`); };
  const declaration = '\ndef descriptor_control_main(name):';
  const dispatch = "if len(sys.argv)==2 and sys.argv[1].startswith('--descriptor-control='):\n    descriptor_control_main(sys.argv[1].split('=',1)[1])";
  const expectedSuffix = `def descriptor_control_main(name):
    cases={
        'false_absent_no_writer':(False,True),
        'false_unrelated_no_writer':(False,False),
        'true_exact_fd10_writer':(True,False),
        'false_fd10_writer':(False,False),
        'false_unrelated_higher_writer':(False,False),
        'false_absent_higher_writer':(False,True),
        'true_missing_fd10':(True,True),
        'true_unrelated_fd10':(True,False),
        'true_exact_plus_extra_writer':(True,False),
    }
    if name not in cases: die(179)
    expected,close_duplicate=cases[name]
    if close_duplicate:
        try:
            os.close(DUP_GUARD)
        except OSError:
            die(180)
    validate_guard_duplicate(expected)
    token=('__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\\t'+name+'\\t0\\n').encode('ascii','strict')
    if os.write(1,token)!=len(token): die(181)
    os._exit(0)

if len(sys.argv)==2 and sys.argv[1].startswith('--descriptor-control='):
    descriptor_control_main(sys.argv[1].split('=',1)[1])
raise SystemExit(main())`;
  const declarationCount = python.split(declaration).length - 1;
  const dispatchCall = "descriptor_control_main(sys.argv[1].split('=',1)[1])";
  const dispatchCallCount = python.split(dispatchCall).length - 1;
  const selectorLines = python.match(/^if len\(sys\.argv\).*$/gm) ?? [];
  const argvCount = python.split('sys.argv').length - 1;
  const declarationAt = python.indexOf(declaration);
  const mainAt = python.indexOf('\ndef main():');
  const program = uniqueSourceRegion(source, 'const planBrokerCPUUnitHolderProgram = `', '\ntype planBrokerCPUUnitHolder struct {').replace(/\r?\n+$/, '');
  if (declarationCount !== 1) fail('descriptor declaration must occur exactly once');
  if (selectorLines.length !== 1 || dispatchCallCount !== 1) fail('fixed descriptor selector and dispatch call must each occur exactly once');
  if (selectorLines[0] !== "if len(sys.argv)==2 and sys.argv[1].startswith('--descriptor-control='):") fail('descriptor selector must retain its exact two-argument fixed prefix');
  if (argvCount !== 3) fail('sys.argv may occur only in the three fixed references inside the private dispatch suffix');
  if (mainAt < 0 || declarationAt <= mainAt) fail('the descriptor suffix must follow the ordinary main definition');
  const expectedPythonSuffix = expectedSuffix.slice(0, expectedSuffix.lastIndexOf('\nraise SystemExit(main())') + 1);
  if (!python.endsWith(expectedPythonSuffix)) fail('the exact descriptor suffix and fixed selector must follow main unchanged');
  if (!program.endsWith(expectedSuffix + '\x60')) fail('the fixed descriptor suffix must end at the ordinary main fallback');
  return true;
}

function validateCapBootstrapSourcePredicate(python) {
  const capBootstrap = uniqueSourceRegion(python, 'def wait_cap_guard_token():', '\ndef control_ready(');
  const helperMain = uniqueSourceRegion(python, 'def main():', 'def descriptor_control_main(name):');
  const readyAt = helperMain.indexOf("control_ready('pre_ready',control_case!='watchdog_absolute_cap')");
  const capWaitCall = "if control_case=='watchdog_absolute_cap':\n                wait_cap_guard_token()";
  const capWaitAt = helperMain.indexOf(capWaitCall, readyAt);
  const capHelperCallAt = helperMain.indexOf('wait_cap_guard_token()', readyAt);
  const tokenReadAt = helperMain.indexOf('token=os.read(GUARD,1)', readyAt);
  const tokenCheckAt = helperMain.indexOf("if token!=b'P': die(110)", tokenReadAt);
  const postTokenGuardAt = helperMain.indexOf('guard_check(True)\n        emit(\'GUARD_READY\')', tokenCheckAt);
  const alarmSetters = [...helperMain.matchAll(/signal\.setitimer\(/g)].map((match) => match.index);
  if (!capBootstrap.includes('signal.pidfd_send_signal(PARENT,0,None,0)') ||
      !capBootstrap.includes('poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)') ||
      !capBootstrap.includes('poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)') ||
      !capBootstrap.includes('events=poller.poll(25)') || !capBootstrap.includes('if any(fd==PARENT for fd,_ in events): die(173)') ||
      !capBootstrap.includes('if mask&(select.POLLHUP|select.POLLERR|select.POLLNVAL): die(174)') ||
      !capBootstrap.includes('if mask&select.POLLIN: return') || !capBootstrap.includes('except ProcessLookupError:') ||
      capBootstrap.includes('guard_check(') || capBootstrap.includes('signal.setitimer(') ||
      readyAt < 0 || capWaitAt <= readyAt || capHelperCallAt <= capWaitAt || tokenReadAt <= capHelperCallAt || tokenCheckAt <= tokenReadAt || postTokenGuardAt <= tokenCheckAt ||
      !helperMain.includes('signal.setitimer(signal.ITIMER_REAL,3.0,0.0)') || alarmSetters.length !== 3 ||
      alarmSetters[0] >= readyAt || alarmSetters[1] >= readyAt || alarmSetters[2] <= postTokenGuardAt ||
      !helperMain.includes("if control_case=='negative_watchdog_omitted':\n                signal.setitimer(signal.ITIMER_REAL,0.0,0.0)")) {
    throw new Error('cap bootstrap source predicate: cap path must poll parent and guard readiness after CONTROL_READY, before the immediate one-byte token read, without guard_check or alarm changes');
  }
  return true;
}

function normalizeHolderMessageCountFunctionRegion(region) {
  const separator = region.match(/\n{1,2}$/)?.[0];
  return separator ? region.slice(0, -separator.length) : null;
}

function validateUnitHolderControlSource(source) {
  const enumRegion = uniqueSourceRegion(source, 'type planBrokerCPUHolderControl string', 'func planBrokerCPUHolderControlTarget(');
  const targets = uniqueSourceRegion(source, 'func planBrokerCPUHolderControlTarget(', 'type planBrokerCPUProcessIdentity struct {');
  const python = uniqueSourceRegion(source, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())`');
  validatePrivateDescriptorSelectorSuffix(source, python);
  validateGuardDescriptorDiagnosticSource(source);
  validateDescriptorGuardControlSource(source);
  const capState = uniqueSourceRegion(python, 'def cap_terminal_state():', '\ndef cap_terminal_wait():');
  const capWait = uniqueSourceRegion(python, 'def cap_terminal_wait():', '\ndef send_reply(frame):');
  const capHealth = uniqueSourceRegion(python, "            if phase=='health_owner':", "            if phase=='unref':");
  const matrix = uniqueSourceRegion(source, 'var planBrokerCPUHolderControlCases = []struct {', 'type planBrokerCPUControlReader struct {');
  const controlRun = uniqueSourceRegion(source, 'func runPlanBrokerCPUHolderControlCase(', 'func runPlanBrokerCPUHolderControlMatrix(');
  const controlParent = uniqueSourceRegion(source, 'func runPlanBrokerCPUHolderControlParent(', '\nfunc planBrokerCPUHolderControlBudget(');
  const controlStart = uniqueSourceRegion(source, 'func startPlanBrokerCPUUnitHolderControl(', 'func readPlanBrokerCPUHolderControlCase(');
  const lifecycle = uniqueSourceRegion(source, 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {', '\nfunc TestCheckpointPlanRelaunchCPUNodeClient(');
  const start = uniqueSourceRegion(source, 'func startPlanBrokerCPUUnitHolderMode(', '\nfunc (holder *planBrokerCPUUnitHolder) send(');
  const accounting = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) send(', '\nfunc (holder *planBrokerCPUUnitHolder) readFrame(');
  const frameReader = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) readFrameUntil(', '\nfunc (holder *planBrokerCPUUnitHolder) health(');
  const expected = new Map([
    ['watchdog_native_expiry', 'pre_ready'], ['watchdog_absolute_cap', 'pre_ready'],
    ['startup_parentdeath', 'startup'], ['parentdeath_pre_ready_after_arm', 'pre_ready'],
    ['parentdeath_import_boundary', 'import'], ['parentdeath_constructor_boundary', 'constructor'],
    ['parentdeath_method_boundary', 'method'], ['parentdeath_held_idle', 'held_idle'],
    ['parentdeath_close_boundary', 'close'], ['parentdeath_after_rearm', 'after_rearm'],
  ]);
  const goCases = new Map([
    ['watchdog_native_expiry', 'planBrokerCPUControlWatchdogNative'], ['watchdog_absolute_cap', 'planBrokerCPUControlWatchdogCap'],
    ['startup_parentdeath', 'planBrokerCPUControlStartupDeath'], ['parentdeath_pre_ready_after_arm', 'planBrokerCPUControlPreReadyDeath'],
    ['parentdeath_import_boundary', 'planBrokerCPUControlImportDeath'], ['parentdeath_constructor_boundary', 'planBrokerCPUControlConstructorDeath'],
    ['parentdeath_method_boundary', 'planBrokerCPUControlMethodDeath'], ['parentdeath_held_idle', 'planBrokerCPUControlHeldIdleDeath'],
    ['parentdeath_close_boundary', 'planBrokerCPUControlCloseDeath'], ['parentdeath_after_rearm', 'planBrokerCPUControlAfterRearmDeath'],
    ['negative_ref_error', 'planBrokerCPUControlNegativeRefError'], ['negative_watchdog_omitted', 'planBrokerCPUControlNegativeWatchdogOmit'],
  ]);
  for (const [name, phase] of expected) {
    const id = goCases.get(name);
    if (!enumRegion.includes(`"${name}"`) || !new RegExp(`${id}\\s+planBrokerCPUHolderControl\\s*=\\s*"${name}"`).test(enumRegion) || !python.includes(`'${name}':('${phase}',`)) throw new Error(`closed holder case name or exact phase is missing: ${name}`);
  }
  for (const phase of new Set(expected.values())) {
    if (!targets.includes(`return "${phase}"`)) throw new Error(`closed holder target phase is missing: ${phase}`);
  }
  if (!targets.includes('default:') || !targets.includes('return ""')) throw new Error('unknown holder control case must remain unavailable');
  if (!capState.includes("signal.getsignal(signal.SIGALRM)!=signal.SIG_DFL") ||
      !capState.includes('signal.pthread_sigmask(signal.SIG_BLOCK,set())') ||
      !capState.includes("('SigBlk:','SigIgn:','SigCgt:','SigPnd:','ShdPnd:')") ||
      !capState.includes('timer[1]!=0.0') || !capState.includes('if left>0 and timer[0]<=0.0: die(162)') ||
      !capWait.includes('signal.pidfd_send_signal(PARENT,0,None,0)') ||
      !capWait.includes('poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)') ||
      !capWait.includes('poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)') ||
      !capWait.includes('poller.register(COMMAND,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)') ||
      !capWait.includes('poller.poll(25)') || capWait.includes('signal.setitimer(') || capWait.includes('die(103)') || capWait.includes('die(134)') || capWait.includes('phase_remaining()') || capWait.includes('guard_check(True)') ||
      !capHealth.includes("if control_case=='watchdog_absolute_cap':") ||
      !capHealth.includes('health_cycles+=1') || !capHealth.includes('if health_cycles>3: die(172)') ||
      !capHealth.includes('if health_cycles==3:') || !capHealth.includes('remaining=deadline-time.monotonic()') ||
      !capHealth.includes('signal.setitimer(signal.ITIMER_REAL,remaining,0.0)') ||
      (capHealth.match(/signal\.setitimer\(/g) ?? []).length !== 1 ||
      !capHealth.includes("phase='cap_terminal'; phase_deadline=None") || /\breturn\b|os\._exit/.test(capWait)) throw new Error('absolute-cap terminal must follow exactly three verified health cycles, arm one residual default alarm, and keep bounded live authority checks without a competing normal exit');
  const capLoop = python.indexOf("if phase=='cap_terminal':\n                cap_terminal_wait()\n                continue");
  if (capLoop < 0 || capLoop > python.indexOf('            guard_check(True)\n            control_ready(\'after_rearm\')')) throw new Error('cap terminal branch must precede all ordinary rearm/deadline logic');
  for (const required of [
    'CONTROL=8', 'BLOCK=9', 'DUP_GUARD=10', 'elif control_case in negative_controls:', 'else: die(131)',
    "raw_control=os.read(CONTROL,80)", "raw_control.count(b'\\n')!=1",
    "if control_case=='watchdog_absolute_cap': deadline=time.monotonic()+10.0",
    "validate_guard_duplicate(control_case=='parentdeath_after_rearm')", 'validate_guard_duplicate(False)',
    'signal.setitimer(signal.ITIMER_REAL,3.0,0.0)', 'signal.pthread_sigmask(signal.SIG_UNBLOCK,{signal.SIGALRM})',
    'if block:', 'part=os.read(BLOCK,1)', 'if part: die(128)',
    "if control_case=='startup_parentdeath':", 'poller.poll(5000)', 'except ProcessLookupError: os._exit(0)',
    "if control_target=='pre_ready' and control_case!='startup_parentdeath':",
    "guard_check(True)\n                control_ready('pre_ready',control_case!='watchdog_absolute_cap')", "guard_check(True)\n                poller=select.poll(); poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR)",
    "control_ready('import')\n                import dbus", "control_ready('constructor')\n                bus=dbus.SystemBus(private=True)",
    "control_ready('method')\n                bus.call_blocking('org.freedesktop.systemd1'",
    "Manager','RefUnit','s',(unit,),timeout=method_timeout()", "Manager','UnrefUnit','s',(unit,),timeout=method_timeout()",
    'def phase_remaining():', 'def method_timeout():', 'return min(2.0,phase_remaining())', 'phase_deadline=min(deadline,time.monotonic()+5.0)', 'phase_deadline=min(deadline,time.monotonic()+3.0)',
    "if control_case=='watchdog_absolute_cap': deadline=time.monotonic()+10.0", "phase='health_owner'",
    "emit('REF_READY\\t'+sender+'\\t'+owner); phase='held'; phase_deadline=None\n                control_ready('held_idle')",
    "control_ready('close')\n                bus.call_blocking('org.freedesktop.systemd1'",
    "guard_check(True)\n            control_ready('after_rearm')",
  ]) if (!python.includes(required)) throw new Error(`fixed helper control handshake or phase ordering is missing: ${required}`);
  const duplicateGuard = uniqueSourceRegion(source, 'def validate_guard_duplicate(expected):', '\ndef native_state():');
  for (const required of ['os.fstat(DUP_GUARD)', 'scan_guard_writer_provenance()', 'scanner_number', 'descriptor_identity(duplicate_now)', 'fcntl.fcntl(DUP_GUARD,fcntl.F_GETFL)', 'observation[3]', 'die(151)', 'die(152)', 'die(178)', 'die(195)']) if (!duplicateGuard.includes(required)) throw new Error(`fd10 object-based duplicate guard proof is incomplete: ${required}`);
  const controlReady = uniqueSourceRegion(source, 'def control_ready(target,block=True):', '\ndef main():');
  for (const required of ["if control_case=='parentdeath_after_rearm':", 'extra=os.read(GUARD,2)', 'except BlockingIOError:', "report('GUARD_DUP_NON_EOF')", 'signal.pidfd_send_signal(PARENT,0,None,0)', 'except ProcessLookupError:', "report('GUARD_DUP_PARENT_PIDFD_CONFIRMED')"]) if (!controlReady.includes(required)) throw new Error(`held-parent death is not proven independently of guard EOF: ${required}`);
  validateCapBootstrapSourcePredicate(python);
  const pythonReport = uniqueSourceRegion(source, 'def report(frame):', '\ndef exact_root(');
  for (const required of ['global used', 'len(data)>192', 'used+len(data)>MAX', 'used+=len(data)', 'os.write(1,data)']) if (!pythonReport.includes(required)) throw new Error(`late helper proof output is not included in its bounded transcript: ${required}`);
  for (const required of [
    "negative_controls={", "'negative_ref_error':'ref_error'", "'negative_watchdog_omitted':'watchdog_omitted'",
    "emit('NEGATIVE_READY\\tnegative_watchdog_omitted')", "emit('NEGATIVE_RESULT\\tnegative_ref_error\\tinjected_before_ref')",
    'time.sleep(30.0)', 'die(155)',
  ]) if (!python.includes(required)) throw new Error(`fixed private negative control is missing ${required}`);
  if (/while\s+True\s*:\s*\n\s+time\.sleep\(/.test(python) || /while\s+True\s*:\s*\n\s+pass\b/.test(python)) throw new Error('watchdog omission must use one fixed finite native blocking action, never an unbounded Python loop');
  if (!/else:\n            try:\n                fcntl\.fcntl\(BLOCK,fcntl\.F_GETFD\)\n                die\(132\)\n            except OSError as block_error:\n                if block_error\.errno!=9: raise/.test(python)) throw new Error('normal helper mode must reject an inherited control-block descriptor');
  for (const forbidden of ['os.getenv(', 'exec(', 'eval(', 'Popen(', 'subprocess.', 'systemctl ', 'D-Bus address']) {
    if (python.includes(forbidden)) throw new Error(`fixed helper control must not add a public selector or program boundary: ${forbidden}`);
  }
  for (const required of [
    'controlR, controlW, err = os.Pipe()', 'blockR, blockW, err = os.Pipe()',
    'cmd.ExtraFiles = append(cmd.ExtraFiles, controlR, blockR)', 'if control == planBrokerCPUControlAfterRearmDeath {', 'cmd.ExtraFiles = append(cmd.ExtraFiles, guardW)', 'controlW.Write([]byte(string(control)+"\\n"))',
    'if control != "" {', 'holder.bytes += len(string(control)) + 1', 'planBrokerCPUHolderControlTarget(control) == ""',
  ]) if (!start.includes(required)) throw new Error(`fixed private pipe or transcript bound is missing: ${required}`);
  if (!controlStart.includes("holder.guard.Write([]byte{'P'})") || controlStart.includes('WriteByte(') || !controlStart.includes('planBrokerCPUValidBusName(') || controlStart.includes('checkpointPlanBrokerCPUValidBusName(') ||
      !controlStart.includes('if control == planBrokerCPUControlWatchdogNative { return nil, "", planBrokerCPUJoinPrimaryAbortForHelperRead(planBrokerCPUReasonPipe, err, primary, holder) }') ||
      !controlStart.includes('return nil, "", planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, primary, holder)') ||
      !controlStart.includes('planBrokerCPUJoinPrimaryAbort(planBrokerCPUReasonPipe, planBrokerCPUHolderBranchAt(planBrokerCPUReasonChildHolderHelperShape, errors.New(')) throw new Error('acquisition error path must use the defined validator, checked one-byte guard write, primary-before-abort helper, and separately staged abort result');
  for (const required of ['holder.bytes += n', 'holder.messages++', 'holder.bytes+len(frame) > 1024']) if (!accounting.includes(required)) throw new Error(`fixed control transcript accounting is missing: ${required}`);
  if (!frameReader.includes('frameSize > 192') || !frameReader.includes('holder.bytes+frameSize > 1024') || !frameReader.includes('bytes.IndexByte(holder.readBuffer, \'\\n\')')) throw new Error('coalesced or oversized holder response frames are not bounded and parsed exactly');
  if (!start.includes('if control != "" && (target == "pre_ready" || target == "startup") { return holder, nil }') ||
      !controlStart.includes('if target == "startup" {') ||
      !controlStart.includes('The child itself has not reported GUARD_READY or any control phase.') ||
      !controlStart.includes('return holder, "CONTROL_READY\\t"+string(control)+"\\tstartup", nil')) {
    throw new Error('startup parentdeath must be controller-marked after exact child identity capture, without synthesizing a child readiness report');
  }
  if (!lifecycle.includes('if holder == nil && err == nil') || !lifecycle.includes('provePlanBrokerCPUOmittedHolderRetention(paths, unitIdentity, victimLaunch, victimPIDFD)') || !lifecycle.includes('planBrokerCPUHolderEOFParentAliveOutcome(holder, paths, victimLaunch, rootInfo)')) throw new Error('holder omission/early-release controls lack the exact loaded stopped-unit retention oracle');
  const omittedRetention = uniqueSourceRegion(source, 'func provePlanBrokerCPUOmittedHolderRetention(', '\nfunc TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(');
  if (!omittedRetention.includes('planBrokerCPUFixtureUnitBound(paths, unit)') || !omittedRetention.includes('planBrokerCPULaunchStillCurrent(paths, launch)') || !omittedRetention.includes('waitPlanBrokerCPUStoppedProof(paths, launch, pidfd)') || !omittedRetention.includes('code == "unit_definition_missing"') || !omittedRetention.includes('fmt.Println(planBrokerCPUHolderOmittedDefinitionPredicate)') || !omittedRetention.includes('holder retention oracle: original unit/worker binding') || !omittedRetention.includes('holder retention oracle: exact unit stop failed') || omittedRetention.indexOf('fmt.Println(planBrokerCPUHolderOmittedDefinitionPredicate)') < omittedRetention.indexOf('if err != nil && code == "unit_definition_missing"') || (omittedRetention.match(/fmt\.Println\(planBrokerCPUHolderOmittedDefinitionPredicate\)/g) ?? []).length !== 1 || !source.includes('planBrokerCPUHolderOmittedDefinitionPredicate = "__PLAN_RELAUNCH_HOLDER_RETENTION_MISSING_DEFINITION__"')) throw new Error('omitted-holder marker must be emitted only after the exact missing-definition stopped-unit predicate');
  if (!lifecycle.includes('if holder.releaseDone {') || !lifecycle.includes('if waitCode != "unit_definition_missing"') || !lifecycle.includes('fmt.Println(planBrokerCPUHolderEarlyReleasePredicate)') || lifecycle.indexOf('fmt.Println(planBrokerCPUHolderEarlyReleasePredicate)') < lifecycle.indexOf('if waitCode != "unit_definition_missing"') || (lifecycle.match(/fmt\.Println\(planBrokerCPUHolderEarlyReleasePredicate\)/g) ?? []).length !== 1 || !source.includes('planBrokerCPUHolderEarlyReleasePredicate      = "__PLAN_RELAUNCH_HOLDER_EARLY_RELEASE_MISSING_DEFINITION__"')) throw new Error('early-release marker must be unique and follow the exact released-holder missing-definition predicate');
  const eofAlive = uniqueSourceRegion(source, 'func planBrokerCPUHolderEOFParentAliveOutcome(', '\nfunc (holder *planBrokerCPUUnitHolder) release()');
  for (const required of ['planBrokerCPUPIDFDTarget(int(holder.parent.Fd()))', 'parentTarget != os.Getpid()', 'unix.Poll(parentEvents, 0)', 'status.ExitStatus() != 107 && status.ExitStatus() != 111', 'if holder.guard == nil {', 'return waitExactTerminal()', 'waitExactTerminal := func() error', 'remaining := time.Until(deadline)', 'case <-holder.waitDone:', 'case <-time.After(remaining):', 'holder.assertCurrent()', 'holder.messages != 4+2*holder.healthSites', 'holder.unit != launch.UnitName', 'holder.releaseDone', 'unit.MainPID != launch.PID', 'unit.Invocation != launch.Invocation', 'os.SameFile(rootInfo, currentRoot)', 'holder.closeFiles()', 'planBrokerCPUHolderEOFAlivePredicate']) if (!eofAlive.includes(required)) throw new Error(`EOF-while-parent-alive oracle lacks ${required}`);
  const closedWait = eofAlive.indexOf('if holder.guard == nil {');
  const liveCheck = eofAlive.indexOf('if err := holder.assertCurrent(); err != nil {');
  if (closedWait < 0 || liveCheck < 0 || closedWait > liveCheck || eofAlive.indexOf('return waitExactTerminal()', closedWait) > liveCheck || eofAlive.indexOf('return waitExactTerminal()', liveCheck) < liveCheck || eofAlive.includes('terminalResult()')) throw new Error('closed-writer EOF must await the sole Wait owner and a terminal pidfd race must use only residual time before healthy baseline return');
  if (!source.includes('planBrokerCPUHolderEOFAlivePredicate = "__PLAN_RELAUNCH_HOLDER_EOF_PARENT_ALIVE_CONFIRMED__"') || (source.match(/errors\.New\(planBrokerCPUHolderEOFAlivePredicate\)/g) ?? []).length !== 1) throw new Error('EOF-alive success-qualified predicate must be unique and follow exact terminal/custody proof');
  if (eofAlive.indexOf('holder.closeFiles()') < 0 || eofAlive.indexOf('holder.closeFiles()') > eofAlive.indexOf('errors.New(planBrokerCPUHolderEOFAlivePredicate)') || lifecycle.includes('holder EOF-while-parent-alive oracle: %v')) throw new Error('EOF-alive exact predicate must follow successful descriptor close and generic lifecycle errors must not share its marker');
  const caseRows = [...matrix.matchAll(/\{(planBrokerCPUControl\w+),\s*"([a-z_]+)",\s*(\d+)\s*\*\s*time\.Second\}/g)];
  if (caseRows.length !== 10) throw new Error('holder controls must have exactly ten compiled case rows');
  const pythonRows = [...python.matchAll(/^\s{4}'([a-z_]+)':\('([a-z_]+)',(True|False)\),?$/gm)];
  if (pythonRows.length !== 10 || new Set(pythonRows.map((row) => row[1])).size !== 10) throw new Error('fixed Python helper control table must contain exactly ten unique closed cases');
  for (const [name, phase] of expected) {
    const py = pythonRows.find((row) => row[1] === name);
    const go = caseRows.find((row) => row[1] === goCases.get(name));
    if (!py || py[2] !== phase || !go || go[2] !== phase) throw new Error(`Go/Python control enum, phase and finite case row disagree: ${name}`);
  }
  if (caseRows.some((row) => ![...goCases.values()].includes(row[1]))) throw new Error('Go matrix contains an unknown control case');
  const budgets = caseRows.map((row) => Number(row[3]));
  const matrixRunner = uniqueSourceRegion(source, 'func runPlanBrokerCPUHolderControlMatrix(', '\nfunc startPlanBrokerCPUUnitHolderMode(');
  if (budgets.reduce((sum, value) => sum + value, 0) !== 43 || !matrix.includes('planBrokerCPUHolderControlAggregateBudget = 45 * time.Second') || !matrix.includes('planBrokerCPUHolderControlPostMatrixReserve = 40 * time.Second') || !matrix.includes('planBrokerCPUHolderControlContractCeiling = 90 * time.Second') || !matrix.includes('planBrokerCPUHolderControlWorkerTimeout = 90 * time.Second') || !matrixRunner.includes('workerLaunchRequestedAt.Add(planBrokerCPUHolderControlWorkerTimeout)') || !matrixRunner.includes('workerDeadline.Add(-planBrokerCPUHolderControlPostMatrixReserve)') || !matrixRunner.includes('time.Until(workerDeadline) <= schedule+planBrokerCPUHolderControlPostMatrixReserve') || !matrixRunner.includes('workerRemaining < planBrokerCPUHolderControlPostMatrixReserve')) {
    throw new Error('control schedule must be 43s planned, dynamically capped at 45s, and leave an actual launch-anchored 40s worker reserve');
  }
  for (const row of caseRows) if (![...goCases.values()].includes(row[1]) || [...goCases.entries()].find(([, value]) => value === row[1])?.[0] === undefined || expected.get([...goCases.entries()].find(([, value]) => value === row[1])[0]) !== row[2] || !targets.includes(row[1]) || !targets.includes(`return "${row[2]}"`)) throw new Error(`control table phase differs from its fixed enum: ${row[1]}`);
  const counts = uniqueSourceRegion(source, 'func planBrokerCPUHolderControlMessageCount(', 'func runPlanBrokerCPUHolderControlParent(');
  const expectedMessageCounts = new Map([
    ['planBrokerCPUControlNegativeRefError', 5], ['planBrokerCPUControlNegativeWatchdogOmit', 2],
    ['planBrokerCPUControlWatchdogNative', 2], ['planBrokerCPUControlWatchdogCap', 12],
    ['planBrokerCPUControlStartupDeath', 1], ['planBrokerCPUControlPreReadyDeath', 2],
    ['planBrokerCPUControlImportDeath', 5], ['planBrokerCPUControlConstructorDeath', 5],
    ['planBrokerCPUControlMethodDeath', 5], ['planBrokerCPUControlHeldIdleDeath', 6],
    ['planBrokerCPUControlCloseDeath', 7], ['planBrokerCPUControlAfterRearmDeath', 6],
  ]);
  const countBody = normalizeHolderMessageCountFunctionRegion(counts);
  const countSwitch = countBody?.match(/^func planBrokerCPUHolderControlMessageCount\(control planBrokerCPUHolderControl\) int \{\n\tswitch control \{\n([\s\S]*)\n\t\}\n\}(?![\s\S])/);
  const actualMessageCounts = new Map();
  const countLines = countSwitch?.[1].split('\n') ?? [];
  let sawDefault = false;
  for (let line = 0; line < countLines.length;) {
    if (countLines[line] === '\tdefault:') {
      if (sawDefault || line + 1 !== countLines.length - 1 || countLines[line + 1] !== '\t\treturn 0') throw new Error('fixed exact message-count mapping differs from the closed cases');
      sawDefault = true;
      line += 2;
      continue;
    }
    const caseMatch = countLines[line]?.match(/^\tcase ([A-Za-z0-9_, ]+):$/);
    const returnMatch = countLines[line + 1]?.match(/^\t\treturn ([0-9]+)$/);
    if (!caseMatch || !returnMatch || sawDefault) throw new Error('fixed exact message-count mapping differs from the closed cases');
    const constants = caseMatch[1].split(',').map((constant) => constant.trim());
    if (constants.length === 0 || constants.some((constant) => !expectedMessageCounts.has(constant))) throw new Error('fixed exact message-count mapping differs from the closed cases');
    for (const constant of constants) {
      if (actualMessageCounts.has(constant)) throw new Error('fixed exact message-count mapping differs from the closed cases');
      actualMessageCounts.set(constant, Number(returnMatch[1]));
    }
    line += 2;
  }
  if (!countSwitch || !sawDefault || actualMessageCounts.size !== expectedMessageCounts.size ||
      [...expectedMessageCounts].some(([constant, count]) => actualMessageCounts.get(constant) !== count)) {
    throw new Error('fixed exact message-count mapping differs from the closed cases');
  }
  if (!enumRegion.includes('planBrokerCPUControlNegativeRefError') || !enumRegion.includes('planBrokerCPUControlNegativeWatchdogOmit')) throw new Error('separate private negative control mapping is absent');
  const capCountControl = uniqueSourceRegion(source, 'func verifyPlanBrokerCPUHolderControlMessageCountControls() error {', '\nfunc verifyPlanBrokerCPUFailureMarkerControls() error {');
  const capFrameLines = [...capCountControl.matchAll(/^\t\t"([^"]+)"[,]?$/gm)].map((match) => match[1]);
  const capBootstrapFrames = [
    'control-token:watchdog_absolute_cap\\n',
    'status:CONTROL_READY\\twatchdog_absolute_cap\\tpre_ready\\n',
    'guard-token:P', 'status:GUARD_READY\\n', 'command:ACQUIRE\\n', 'status:REF_READY\\n',
  ];
  const healthFrameSchedule = Array.from({ length: 3 }, () => ['command:HEALTH\\n', 'status:HEALTH_READY\\n']).flat();
  if (JSON.stringify(capFrameLines.slice(0, capBootstrapFrames.length)) !== JSON.stringify(capBootstrapFrames) ||
      JSON.stringify(capFrameLines.slice(capBootstrapFrames.length)) !== JSON.stringify(healthFrameSchedule) ||
      !capCountControl.includes('capExpected := planBrokerCPUHolderControlMessageCount(planBrokerCPUControlWatchdogCap)') ||
      !capCountControl.includes('frameCountMatches(capFrames[:])') || !capCountControl.includes('frameCountMatches(missingFrame)') ||
      !capCountControl.includes('frameCountMatches(extraFrame)') || !capCountControl.includes('planBrokerCPUHolderControlMessageCount(planBrokerCPUControlWatchdogNative) == capExpected')) {
    throw new Error('pure cap message-count control must bind the actual helper to six literal bootstrap frames and three ordered HEALTH pairs, then reject missing, extra, and wrong-case schedules');
  }
  const markerCountControls = uniqueSourceRegion(source, 'func verifyPlanBrokerCPUFailureMarkerControls() error {', '\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {');
  if (!markerCountControls.startsWith('func verifyPlanBrokerCPUFailureMarkerControls() error {\n\tif err := verifyPlanBrokerCPUHolderControlMessageCountControls(); err != nil {\n\t\treturn err\n\t}')) throw new Error('pure cap message-count control must run first in the existing marker-control chain');
  const negativeBudget = uniqueSourceRegion(source, 'func planBrokerCPUHolderNegativeControlBudget(', '\nvar planBrokerCPUHolderControlCases');
  for (const required of ['planBrokerCPUControlNegativeRefError', '8 * time.Second', 'planBrokerCPUControlNegativeWatchdogOmit', '12 * time.Second', 'default:', 'return 0']) if (!negativeBudget.includes(required)) throw new Error(`negative holder control budget is not closed/bounded: ${required}`);
  const lifecycleTest = uniqueSourceRegion(source, 'func TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {', '\nfunc TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {');
  for (const required of [
    'planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit',
    'planBrokerCPUHolderNegativeControl == ""',
    'isPlanBrokerCPUInjectedRefError(err)',
    'negative_ref_error: normal holder acquisition consumed the exact injected pre-RefUnit error',
    'fmt.Println(planBrokerCPUHolderRefErrorNotConsumedPredicate)',
    'negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned',
    'fmt.Println(planBrokerCPUHolderWatchdogOracleBypassedPredicate)',
  ]) if (!lifecycleTest.includes(required)) throw new Error(`fixed negative holder control does not prove its bounded behavior: ${required}`);
  if (!lifecycleTest.includes('if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {\n\t\tcontrolDeadline := time.Now().Add(planBrokerCPUHolderNegativeControlBudget(planBrokerCPUControlNegativeWatchdogOmit))\n\t\terr := runPlanBrokerCPUHolderControlCase')) throw new Error('watchdog omission token must reach its actual parentdeath survivor oracle');
  const acquisition = uniqueSourceRegion(source, 'func startPlanBrokerCPUUnitHolder(', '\nvar errPlanBrokerCPUInjectedRefError');
  if (!acquisition.includes('control := planBrokerCPUHolderNegativeControl') || !acquisition.includes('NEGATIVE_RESULT\\tnegative_ref_error\\tinjected_before_ref') || !acquisition.includes('ExitStatus() != 148') || !acquisition.includes('return nil, errPlanBrokerCPUInjectedRefError')) throw new Error('negative RefUnit case must traverse the real holder acquisition call and propagate only the fixed synthetic error');
  const watchdogParent = uniqueSourceRegion(source, 'func runPlanBrokerCPUHolderControlCase(', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  for (const required of ['if control == planBrokerCPUControlNegativeWatchdogOmit', 'terminalDeadline := time.Now().Add(5*time.Second)', 'parentWaitErr := waitUntil(terminalDeadline)', 'for time.Now().Before(terminalDeadline)', 'unix.PidfdSendSignal(helperPIDFD, syscall.SIGKILL', 'waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, cleanupDeadline)', 'negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned']) if (!watchdogParent.includes(required)) throw new Error(`watchdog negative lacks its same-original-deadline survivor proof: ${required}`);
  const leakedWriter = uniqueSourceRegion(source, 'func runPlanBrokerCPUHolderControlCase(', '\nfunc runPlanBrokerCPUHolderControlMatrix(');
  for (const required of ['control == planBrokerCPUControlAfterRearmDeath', 'nonEOF != "GUARD_DUP_NON_EOF"', 'confirmed != "GUARD_DUP_PARENT_PIDFD_CONFIRMED"', 'lateProofBytes := len("GUARD_DUP_NON_EOF\\n") + len("GUARD_DUP_PARENT_PIDFD_CONFIRMED\\n")', 'transcriptBytes+lateProofBytes > 1024', 'transcriptMessages+2 != planBrokerCPUHolderControlMessageCount(control)', 'parentWaitErr := waitUntil(terminalDeadline)', 'waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, terminalDeadline)', 'stdoutReader.requireEOF(until)', 'stdoutReader.messages != planBrokerCPUHolderControlReportMessageCount(control)', 'stdoutReader.bytes > 1024', 'stdoutReader.maxFrame > 192']) if (!leakedWriter.includes(required)) throw new Error(`leaked-writer parentdeath result lacks its actual bounded held-parent report settlement: ${required}`);
  if ((start.match(/cmd\.Stdout\s*=/g) ?? []).length !== 1 || !start.includes('if control == planBrokerCPUControlAfterRearmDeath {\n\t\tcmd.Stdout = os.Stdout\n\t}')) throw new Error('only parentdeath_after_rearm may forward helper stdout into the outer report pipe');
  if (!leakedWriter.includes('command.Stdout = reportW') || !leakedWriter.includes('stdoutReader.requireEOF(until)') || !leakedWriter.includes('requireReportEOF(terminalDeadline, planBrokerCPUReasonPipe)') || !leakedWriter.includes('stdoutReader.messages != planBrokerCPUHolderControlReportMessageCount(control)')) throw new Error('outer report pipe must consume exact bounded records and EOF after the confirmed child terminal');
  const reportEOF = uniqueSourceRegion(source, 'func (reader *planBrokerCPUControlReader) requireEOF(', '\nfunc planBrokerCPUHolderControlReportMessageCount(');
  const reportRead = uniqueSourceRegion(source, 'func (reader *planBrokerCPUControlReader) read(', '\nfunc (reader *planBrokerCPUControlReader) requireEOF(');
  for (const required of ['len(reader.buffer) != 0', 'reader.file.Read(extra[:])', 'n != 0', 'errors.Is(err, io.EOF)', 'time.Now().Before(deadline)']) if (!reportEOF.includes(required)) throw new Error(`outer report reader does not reject duplicate, trailing, or unbounded records: ${required}`);
  for (const required of ['reader.bytes+frameSize > 1024', 'frameSize > 192', 'reader.messages++', 'reader.maxFrame = frameSize', 'reader.buffer[:newline]']) if (!reportRead.includes(required)) throw new Error(`outer report reader does not reject malformed or overflow frames: ${required}`);
  for (const required of [
    'context.WithDeadline(context.Background(), deadline)', 'unitBefore.MainPID != launch.PID',
    'unitBefore.Invocation != launch.Invocation', 'unitBefore.Active != "active"',
    'planBrokerCPULaunchStillCurrent(paths, launch)', 'syscall.SIGKILL', 'unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL',
    'waitPlanBrokerCPUHolderTerminal(helperPIDFD, helperPID, helperStart, terminalDeadline)',
    'planBrokerCPULaunchStillCurrent(paths, launch) != nil', 'os.SameFile(rootInfo, currentRoot)',
    'transcriptBytes > 1024', 'maximumFrame > 192', 'transcriptMessages != expectedMessagesBeforeDeath',
    'stdoutReader.requireEOF(until)', 'stdoutReader.messages != planBrokerCPUHolderControlReportMessageCount(control)',
  ]) if (!controlRun.includes(required)) throw new Error(`controlled phase does not preserve bounded parentdeath and original worker/root proofs: ${required}`);
  if (!controlRun.includes('reportR, reportW, err := os.Pipe()') || !controlRun.includes('command.Stdout = reportW') || !controlRun.includes('reportW.Close()') || controlRun.includes('command.StdoutPipe()')) throw new Error('control stdout custody must use an owned private report pipe independent of Wait-managed stdout closure');
  if (!controlRun.includes('parentPIDFD := -1') || !controlRun.includes('waitUntil := func(until time.Time) error') || !controlRun.includes('go func() { waitResult <- command.Wait() }()') || (controlRun.match(/command\.Wait\(\)/g) ?? []).length !== 1 || !controlRun.includes('parentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(command.Process.Pid)') || !controlRun.includes('identity, identityErr = capturePlanBrokerCPUProcessIdentity(helperPID)') || !controlRun.includes('parentValidated = true') || !controlRun.includes('currentParent != parentIdentity') || !controlRun.includes('helperCurrent != helperIdentity')) throw new Error('control parent/helper custody requires initialized identities, one bounded Wait owner and full identity rechecks before signal');
  if (!controlRun.includes('CONTROL_RESULT\\t') || !controlRun.includes('watchdog_sigalrm') || !controlParent.includes('status.Signal() != syscall.SIGALRM')) throw new Error('watchdog positive must prove actual default SIGALRM termination');
  for (const required of [
    'for index := 0; index < 3; index++', 'time.Sleep(2 * time.Second)', 'holder.send("HEALTH\\n")',
    'holder.readFrameUntil(controlDeadline)', 'response != "HEALTH_READY"', 'holder.healthSites++',
  ]) if (!controlParent.includes(required)) throw new Error(`shortened-cap control lacks real same-connection progress: ${required}`);
  if ((controlRun.match(/context\.WithDeadline\(context\.Background\(\), deadline\)/g) ?? []).length !== 4) throw new Error('each control case must bound pre-state, watchdog, parentdeath and omission post-state queries by the same original case deadline');
  const terminalDeadlineAt = controlRun.indexOf('terminalDeadline := time.Now().Add(5*time.Second)');
  const killAt = controlRun.indexOf('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)', terminalDeadlineAt);
  if (terminalDeadlineAt < 0 || killAt < 0 || terminalDeadlineAt > killAt || !controlRun.includes('parentWaitErr := waitUntil(terminalDeadline)')) throw new Error('parent Wait and helper terminal settlement must share the absolute five-second deadline started before exact pidfd SIGKILL');
  if (!lifecycle.includes('runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)') || !lifecycle.includes('initialWorkerLaunchRequestedAt := time.Now()')) throw new Error('ten-case matrix must use the actual captured original worker and launch-anchored deadline before the normal holder');
  const matrixCall = lifecycle.indexOf('runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)');
  const ordinaryHolder = lifecycle.indexOf('startPlanBrokerCPUUnitHolder(paths, rootInfo, victimLaunch', matrixCall);
  const firstStop = lifecycle.indexOf('stopPlanBrokerCPUUnit(unitIdentity)', matrixCall);
  if (matrixCall < 0 || ordinaryHolder <= matrixCall || firstStop <= matrixCall) throw new Error('control matrix must precede normal holder acquisition and every stop');
  const holderType = uniqueSourceRegion(source, 'type planBrokerCPUUnitHolder struct {', 'type planBrokerCPUHolderControl string');
  if (!holderType.includes('abortDone') || !holderType.includes('abortErr') || !holderType.includes('closeErr') || !holderType.includes('releaseDone') || !holderType.includes('releaseErr')) throw new Error('holder lifecycle must latch the one abort, release and close outcome');
  const abort = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) abort() error {', '\nfunc (holder *planBrokerCPUUnitHolder) closeFiles()');
  if (!abort.includes('if holder.abortDone { return holder.abortErr }') || !abort.includes('deadline := time.Now().Add(5 * time.Second)') || (abort.match(/time\.After\(5\s*\*\s*time\.Second\)/g) ?? []).length !== 0 || !abort.includes('holder.abortErr = errors.Join(result, holder.closeFiles())')) throw new Error('abort must latch failure and use one total five-second settlement deadline');
  const release = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) release() error {', '\nfunc (holder *planBrokerCPUUnitHolder) abort()');
  if (!release.includes('holder.requireStatusEOFUntil(deadline)')) throw new Error('normal release must use the original absolute phase deadline for exact EOF');
  const statusEOF = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(', '\nfunc (holder *planBrokerCPUUnitHolder) abort()');
  if (!statusEOF.includes('unix.Poll(poll, ms)') || !statusEOF.includes('holder.status.Read(trailing[:])') || !statusEOF.includes('errors.Is(readErr, io.EOF)') || !statusEOF.includes('time.Now().Before(deadline)')) throw new Error('normal release final EOF read must be readiness-polled and bounded by the same deadline');
  const closeFiles = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) closeFiles() error {', '\nfunc planBrokerCPUHolderIdentityCurrent(');
  if (!closeFiles.includes('if holder.closed { return holder.closeErr }') || !closeFiles.includes('holder.closeErr = result') || !closeFiles.includes('*file = nil') || !closeFiles.includes('holder.childPIDFD = -1')) throw new Error('descriptor close uncertainty must remain latched and owned descriptors detached after their one close');
  return true;
}

const expectedUnitHolderControlEvents = [
  ['watchdog_native_expiry', 'pre_ready'], ['watchdog_absolute_cap', 'pre_ready'],
  ['startup_parentdeath', 'startup'], ['parentdeath_pre_ready_after_arm', 'pre_ready'],
  ['parentdeath_import_boundary', 'import'], ['parentdeath_constructor_boundary', 'constructor'],
  ['parentdeath_method_boundary', 'method'], ['parentdeath_held_idle', 'held_idle'],
  ['parentdeath_close_boundary', 'close'], ['parentdeath_after_rearm', 'after_rearm'],
];
const unitHolderMatrixEventPrefix = '__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL_MATRIX__';
const unitHolderMatrixEventPattern = /^__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL_MATRIX__ cases=10 budget_ms=45000 worker_ms=90000 reserve_ms=40000 elapsed_ms=(\d+) worker_remaining_ms=(\d+)$/;

function validateUnitHolderControlEvents(output) {
  if (typeof output !== 'string') throw new Error('controlled holder event output is not text');
  const observed = [], matrices = [];
  for (const line of output.split(/\r?\n/)) {
    if (line.startsWith('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__')) {
      const match = line.match(/^__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\t([a-z_]+)\t([a-z_]+)$/);
      if (!match) throw new Error('controlled holder event has an unknown shape');
      observed.push([match[1], match[2]]);
    }
    if (line.startsWith(unitHolderMatrixEventPrefix)) matrices.push(line);
  }
  const matrix = matrices.length === 1 ? matrices[0].match(unitHolderMatrixEventPattern) : null;
  const elapsed = matrix ? Number(matrix[1]) : NaN;
  const workerRemaining = matrix ? Number(matrix[2]) : NaN;
  if (JSON.stringify(observed) !== JSON.stringify(expectedUnitHolderControlEvents) || !matrix || !Number.isSafeInteger(elapsed) || elapsed < 0 || elapsed > 45000 || !Number.isSafeInteger(workerRemaining) || workerRemaining < 40000 || workerRemaining > 90000) {
    throw new Error('controlled holder event inventory, order, or bounded matrix receipt is not exact');
  }
  return true;
}

function selfTestUnitHolderControlSource(source, verifier) {
  validateUnitHolderControlSource(source);
  const countRegion = uniqueSourceRegion(source, 'func planBrokerCPUHolderControlMessageCount(', '\nfunc runPlanBrokerCPUHolderControlParent(');
  const countBody = normalizeHolderMessageCountFunctionRegion(countRegion);
  if (countBody === null || normalizeHolderMessageCountFunctionRegion(`${countBody}\n`) !== countBody ||
      normalizeHolderMessageCountFunctionRegion(`${countBody}\n\n`) !== countBody) {
    throw new Error('actual message-count function positive must normalize one or two separator LFs to the same exact body');
  }
  const countMappingFailure = 'fixed exact message-count mapping differs from the closed cases';
  const mutateCountRegionOnce = (region, before, after, label) => {
    if (region.split(before).length !== 2) throw new Error(`message-count mutation anchor is not unique: ${label}`);
    return region.replace(before, after);
  };
  const expectCountMappingRejection = (mutatedRegion, label) => {
    if (mutatedRegion === countRegion) throw new Error(`message-count mutation did not change the owning function: ${label}`);
    if (source.split(countRegion).length !== 2) throw new Error('actual message-count function boundary is not unique');
    const mutantSource = source.replace(countRegion, mutatedRegion);
    let reason = '';
    try { validateUnitHolderControlSource(mutantSource); }
    catch (error) { reason = String(error?.message ?? error); }
    if (reason !== countMappingFailure) throw new Error(`message-count source control missed ${label}: ${reason || 'accepted'}`);
  };
  const expectMalformedCountRegionRejection = (mutatedRegion, label) => {
    if (mutatedRegion === countRegion || source.split(countRegion).length !== 2) throw new Error(`message-count boundary mutation is not branch-bound: ${label}`);
    const mutantSource = source.replace(countRegion, mutatedRegion);
    let reason = '';
    try { validateUnitHolderControlSource(mutantSource); }
    catch (error) { reason = String(error?.message ?? error); }
    if (reason !== countMappingFailure) throw new Error(`message-count boundary source control missed ${label}: ${reason || 'accepted'}`);
  };
  const oneSeparatorSource = source.replace(countRegion, `${countBody}\n`);
  const twoSeparatorSource = source.replace(countRegion, `${countBody}\n\n`);
  for (const [variant, candidate] of [['one separator LF', oneSeparatorSource], ['two separator LFs', twoSeparatorSource]]) {
    if (source.split(countRegion).length !== 2 || (variant === 'one separator LF' && candidate === source) ||
        (variant === 'two separator LFs' && candidate !== source)) throw new Error(`message-count separator positive is not branch-bound: ${variant}`);
    try { validateUnitHolderControlSource(candidate); }
    catch (error) { throw new Error(`actual message-count function rejected ${variant}: ${String(error?.message ?? error)}`); }
  }
  expectMalformedCountRegionRejection(`${countBody}\n\tunexpected_count_body_token\n\n`, 'extra non-whitespace body token');
  expectMalformedCountRegionRejection(`${countBody.slice(0, -1)}\n\n`, 'missing function closure');
  expectMalformedCountRegionRejection(`${countBody}\n\n\n`, 'extra function-separator LF');
  const capCountRow = '\tcase planBrokerCPUControlWatchdogCap:\n\t\treturn 12';
  for (const count of [11, 13, 0]) {
    expectCountMappingRejection(
      mutateCountRegionOnce(countRegion, capCountRow, capCountRow.replace('return 12', `return ${count}`), `cap=${count}`),
      `obsolete/wrong absolute-cap count ${count}`,
    );
  }
  const nativeCountRow = '\tcase planBrokerCPUControlWatchdogNative, planBrokerCPUControlPreReadyDeath:\n\t\treturn 2';
  const splitNativeCountRow = '\tcase planBrokerCPUControlWatchdogNative:\n\t\treturn 12\n\tcase planBrokerCPUControlPreReadyDeath:\n\t\treturn 2';
  expectCountMappingRejection(
    mutateCountRegionOnce(countRegion, nativeCountRow, splitNativeCountRow, 'changed non-cap case'),
    'changed non-cap case count',
  );
  let permutedCountRegion = mutateCountRegionOnce(countRegion, nativeCountRow, splitNativeCountRow, 'permuted native count');
  permutedCountRegion = mutateCountRegionOnce(permutedCountRegion, capCountRow, capCountRow.replace('return 12', 'return 2'), 'permuted cap count');
  expectCountMappingRejection(permutedCountRegion, 'permuted cap/native mapping');
  expectCountMappingRejection(
    mutateCountRegionOnce(countRegion, nativeCountRow, nativeCountRow.replace('planBrokerCPUControlPreReadyDeath', 'planBrokerCPUControlWatchdogCap'), 'duplicate case'),
    'duplicate case binding',
  );
  const startupDeathRow = '\tcase planBrokerCPUControlStartupDeath:\n\t\treturn 1\n';
  expectCountMappingRejection(mutateCountRegionOnce(countRegion, startupDeathRow, '', 'missing case'), 'missing case binding');
  const unknownCaseRegion = `${countRegion.replace('\n\tdefault:', '\n\tcase planBrokerCPUControlUnlisted:\n\t\treturn 12\n\tdefault:')}`;
  expectCountMappingRejection(unknownCaseRegion, 'unknown case binding');
  const python = uniqueSourceRegion(source, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())`');
  validateCapBootstrapSourcePredicate(python);
  const suffixMutant = (needle, replacement, label, intended) => {
    if (source.split(needle).length !== 2) throw new Error(`private descriptor suffix mutant anchor is not unique: ${label}`);
    const mutant = source.replace(needle, replacement);
    const mutantPython = uniqueSourceRegion(mutant, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())`');
    let reason = '';
    try { validatePrivateDescriptorSelectorSuffix(mutant, mutantPython); }
    catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`fixed helper descriptor suffix predicate: ${intended}`)) throw new Error(`private descriptor suffix control missed ${label}'s intended first rejection: ${reason || 'accepted'}`);
  };
  suffixMutant(
    "if len(sys.argv)==2 and sys.argv[1].startswith('--descriptor-control='):\n    descriptor_control_main(sys.argv[1].split('=',1)[1])",
    "if len(sys.argv)>=2 and sys.argv[1].startswith('--descriptor-control='):\n    descriptor_control_main(sys.argv[1].split('=',1)[1])",
    'widened descriptor selector', 'descriptor selector must retain its exact two-argument fixed prefix',
  );
  suffixMutant(
    'def main():\n    global used,buffer,bus,sender,owner,unit,phase,phase_deadline,control_case,control_target,deadline,health_cycles',
    'def main():\n    # sys.argv is forbidden outside the fixed descriptor suffix\n    global used,buffer,bus,sender,owner,unit,phase,phase_deadline,control_case,control_target,deadline,health_cycles',
    'extra argv reference outside suffix', 'sys.argv may occur only in the three fixed references inside the private dispatch suffix',
  );
  const suffixStart = source.indexOf('\ndef descriptor_control_main(name):');
  const suffixFallback = source.indexOf('\nraise SystemExit(main())`', suffixStart);
  if (suffixStart < 0 || suffixFallback <= suffixStart || source.indexOf('\ndef descriptor_control_main(name):', suffixStart + 1) >= 0) throw new Error('private descriptor suffix control boundary is missing or ambiguous');
  const originalSuffix = source.slice(suffixStart + 1, suffixFallback);
  const replaceCompleteSuffix = (replacement) => source.slice(0, suffixStart + 1) + replacement + source.slice(suffixFallback);
  const checkCompleteSuffix = (mutant, label, intended) => {
    const mutantPython = uniqueSourceRegion(mutant, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())`');
    let reason = '';
    try { validatePrivateDescriptorSelectorSuffix(mutant, mutantPython); }
    catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`fixed helper descriptor suffix predicate: ${intended}`)) throw new Error(`private descriptor suffix control missed ${label}'s intended first rejection: ${reason || 'accepted'}`);
  };
  checkCompleteSuffix(replaceCompleteSuffix(''), 'missing descriptor suffix', 'descriptor declaration must occur exactly once');
  checkCompleteSuffix(replaceCompleteSuffix(`${originalSuffix}\n${originalSuffix}`), 'duplicate descriptor suffix', 'descriptor declaration must occur exactly once');
  for (const [from, to, intended] of [
    ['assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_fd10_writer")', 'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_unrelated_higher_writer")', 'false_fd10_writer'],
    ['assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_unrelated_higher_writer")', 'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "false_fd10_writer")', 'false_unrelated_higher_writer'],
    ['assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_unrelated_fd10")', 'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_exact_plus_extra_writer")', 'true_unrelated_fd10'],
    ['assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_exact_plus_extra_writer")', 'assertPlanBrokerCPUDescriptorGuardMutantDetected(t, "true_unrelated_fd10")', 'true_exact_plus_extra_writer'],
  ]) {
    if (source.split(from).length !== 2) throw new Error(`descriptor mutant mapping source anchor is not unique: ${intended}`);
    let reason = '';
    try { validateDescriptorGuardControlSource(source.replace(from, to)); }
    catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`descriptor guard control source predicate: compiled mutant test `) || !reason.includes(`decisive case ${intended}`)) {
      throw new Error(`descriptor mutant mapping control missed its first intended rejection (${intended}): ${reason || 'accepted'}`);
    }
  }
  selfTestGuardDescriptorDiagnosticSource(source);
  const descriptorClassifier = uniqueSourceRegion(verifier, 'function classifyDescriptorGuardControlResult(result) {', '\nfunction selfTestDescriptorGuardControlResult() {');
  for (const required of [
    'result.error', 'result.status === null', 'result.status !== 0',
    'exactInventory(output, [descriptorGuardControlTest])',
    'parentRunIndex < 0 || parentPassIndex <= parentRunIndex',
    'index <= parentRunIndex || index >= parentPassIndex',
    'line.match(/^__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_CASE__\\t([a-z0-9_]+)\\t(0|[1-9][0-9]{0,2})$/)',
    'JSON.stringify(observed) !== JSON.stringify(descriptorGuardControlCases)',
  ]) if (!descriptorClassifier.includes(required)) throw new Error(`descriptor result classifier lost a closed requirement: ${required}`);
  const descriptorClassifierControls = uniqueSourceRegion(verifier, 'function selfTestDescriptorGuardControlResult() {', '\nconst inactiveWaitOwners = [');
  for (const required of ['all case markers before parent RUN', 'all case markers after parent PASS', 'single case marker crossing parent interval']) {
    if (!descriptorClassifierControls.includes(required)) throw new Error(`descriptor result classifier lost its temporal control: ${required}`);
  }
  if (!verifier.includes('selfTestDescriptorGuardControlResult();')) throw new Error('descriptor result classifier known-positive and negative controls are not invoked by source-only preflight');
  const descriptorInventoryConsumer = uniqueSourceRegion(verifier, 'function executeInventory(', '\nfunction withPrivateBinary(');
  const exactEventCall = 'if (expected.includes(descriptorGuardControlTest)) {\n    try { classifyDescriptorGuardControlResult(result); }';
  if (!descriptorInventoryConsumer.includes(exactEventCall) || descriptorInventoryConsumer.indexOf('exactInventory(output, expected)') >= descriptorInventoryConsumer.indexOf(exactEventCall)) throw new Error('actual positive descriptor inventory does not consume the strict nine-event classifier after exact top-level RUN/PASS validation');
  const descriptorMutants = uniqueSourceRegion(verifier, 'function verifyCompiledDescriptorGuardMutants(temp, mode) {', '\nfunction executeInventory(');
  for (const required of [
    "if (mode !== 'reconcile' && mode !== 'cpu-sequence')",
    "'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=false_fd10_writer'",
    "'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=false_unrelated_higher_writer'",
    "'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=true_unrelated_fd10'",
    "'__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=true_exact_plus_extra_writer'",
    "'TestPlanBrokerCPUDescriptorGuardMutantFD10'", "'TestPlanBrokerCPUDescriptorGuardMutantHigher'",
    "'TestPlanBrokerCPUDescriptorGuardMutantWrongFD10'", "'TestPlanBrokerCPUDescriptorGuardMutantExtraWriter'",
    'descriptor-fd10-writer-accepted-', 'descriptor-higher-writer-accepted-',
    'descriptor-wrong-fd10-object-accepted-', 'descriptor-extra-writer-accepted-',
    'if False and duplicate_observation[2]', 'if False and any(observation[3] for observation in observations.values())',
    "if duplicate_observation is None or duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY:",
    'if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):',
    "'checkpoint_plan_broker_cpu', false",
  ]) if (!descriptorMutants.includes(required)) throw new Error(`compiled descriptor mutant source is incomplete: ${required}`);
  if ((descriptorMutants.match(/compileBehavioralMutant\(/g) ?? []).length !== 4) throw new Error('descriptor guard behavioral controls must retain exactly four bounded coupled mutants');
  const descriptorMutantBlocks = descriptorMutants.split('\n  compileBehavioralMutant(').slice(1);
  const expectedMutantBindings = [
    ['descriptor-fd10-writer-accepted-', 'TestPlanBrokerCPUDescriptorGuardMutantFD10', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=false_fd10_writer', [
      '        if duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)',
      '        if any(observation[3] for observation in observations.values()):\n            die(195)',
    ]],
    ['descriptor-higher-writer-accepted-', 'TestPlanBrokerCPUDescriptorGuardMutantHigher', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=false_unrelated_higher_writer', [
      '        if any(observation[3] for observation in observations.values()):\n            die(195)',
    ]],
    ['descriptor-wrong-fd10-object-accepted-', 'TestPlanBrokerCPUDescriptorGuardMutantWrongFD10', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=true_unrelated_fd10', [
      '            if duplicate_observation is None or duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY:',
    ]],
    ['descriptor-extra-writer-accepted-', 'TestPlanBrokerCPUDescriptorGuardMutantExtraWriter', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\\tcase=true_exact_plus_extra_writer', [
      '            if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):',
    ]],
  ];
  if (descriptorMutantBlocks.length !== expectedMutantBindings.length) throw new Error('compiled descriptor mutant blocks are not an exact four-entry inventory');
  for (const [index, [name, testName, marker, anchors]] of expectedMutantBindings.entries()) {
    const block = descriptorMutantBlocks[index];
    if (!block.includes(name) || !block.includes(`'${testName}'`) || !block.includes(`'${marker}'`)) throw new Error(`compiled descriptor mutant ${name} is not bound to its exact selected test and failure identity`);
    for (const anchor of anchors) {
      const sourceLiteral = JSON.stringify(anchor).slice(1, -1);
      if (source.split(anchor).length !== 2 || block.split(sourceLiteral).length !== 2) throw new Error(`compiled descriptor mutant ${name} lacks its unique intended source anchor`);
    }
  }
  const immediateCapRead = "if control_case=='watchdog_absolute_cap':\n                wait_cap_guard_token()";
  if (source.split(immediateCapRead).length !== 2) throw new Error('cap bootstrap mutation anchor is not unique');
  const capMutant = source.replace(immediateCapRead, "if control_case=='watchdog_absolute_cap':\n                token=os.read(GUARD,1)");
  const capMutantPython = uniqueSourceRegion(capMutant, 'const planBrokerCPUUnitHolderProgram = `', 'raise SystemExit(main())`');
  const capDiagnostic = 'cap bootstrap source predicate: cap path must poll parent and guard readiness after CONTROL_READY, before the immediate one-byte token read, without guard_check or alarm changes';
  let capPredicateReason = '';
  try { validateCapBootstrapSourcePredicate(capMutantPython); }
  catch (error) { capPredicateReason = String(error?.message ?? error); }
  if (capPredicateReason !== capDiagnostic) {
    throw new Error(`cap bootstrap immediate-read mutant missed its owning predicate: ${capPredicateReason || 'accepted'}`);
  }
  let fullValidatorRejectedCapMutant = false;
  try { validateUnitHolderControlSource(capMutant); }
  catch { fullValidatorRejectedCapMutant = true; }
  if (!fullValidatorRejectedCapMutant) throw new Error('full holder source validator accepted the cap bootstrap immediate-read mutant');
  const execution = uniqueSourceRegion(verifier, 'function executeInventory(', 'function withPrivateBinary(');
  if (!execution.includes("expected.includes('TestCheckpointPlanRelaunchCPULifecycleSequence')") || !execution.includes('validateUnitHolderControlEvents(output);')) throw new Error('actual lifecycle execution must consume the exact ten-case event transcript');
  const descriptorBranchSpec = [
    ['reconcile', "} else if (mode === '--mode=reconcile') {", "} else {\n      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'"],
    ['cpu-sequence', "} else {\n      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'", '\n    }\n  } finally {'],
  ];
  const descriptorBranch = (verifierSource, mode) => {
    const modes = uniqueSourceRegion(verifierSource, 'function withPrivateBinary(mode) {', '\nconst recoveryPolicyTests = [');
    const spec = descriptorBranchSpec.find(([candidate]) => candidate === mode);
    if (!spec) throw new Error(`descriptor branch mode is unknown: ${mode}`);
    const [, startText, endText] = spec;
    if (modes.split(startText).length !== 2) throw new Error(`actual descriptor branch start is not unique: ${mode}`);
    const start = modes.indexOf(startText);
    const end = modes.indexOf(endText, start + startText.length);
    if (start < 0 || end <= start || modes.split(endText).length !== 2) throw new Error(`actual descriptor branch boundary is missing or ambiguous: ${mode}`);
    return { modes, start, end, branch: modes.slice(start, end) };
  };
  const mutateActualDescriptorBranch = (verifierSource, mode, mutate) => {
    const { modes, start, end, branch } = descriptorBranch(verifierSource, mode);
    const changed = mutate(branch);
    if (changed === branch) throw new Error(`actual descriptor branch mutation did not change ${mode}`);
    const changedModes = modes.slice(0, start) + changed + modes.slice(end);
    if (verifierSource.split(modes).length !== 2) throw new Error('actual withPrivateBinary source region is not unique');
    const mutated = verifierSource.replace(modes, changedModes);
    const otherMode = mode === 'reconcile' ? 'cpu-sequence' : 'reconcile';
    if (descriptorBranch(mutated, otherMode).branch !== descriptorBranch(verifierSource, otherMode).branch) {
      throw new Error(`actual descriptor mutation changed unrelated ${otherMode} branch`);
    }
    return mutated;
  };
  const requireDescriptorOrder = (verifierSource) => {
    for (const [mode] of descriptorBranchSpec) {
      const { branch } = descriptorBranch(verifierSource, mode);
      const calls = [
        "executeInventory(binary, ['TestPlanBrokerCPUFailureMarkerControlsPure'], 60, false);",
        "executeInventory(binary, ['TestPlanBrokerCPUDescriptorGuardControls'], 60, false);",
        `verifyCompiledHolderDiagnosticMutants(temp, '${mode}');`,
        `verifyCompiledDescriptorGuardMutants(temp, '${mode}');`,
        'const output = executeInventory(binary, selected, 240, true);',
      ];
      const positions = calls.map((call) => branch.indexOf(call));
      if (positions.some((at) => at < 0) || positions.some((at, index) => index > 0 && at <= positions[index - 1]) ||
          calls.some((call) => branch.split(call).length !== 2)) throw new Error(`descriptor controls must run positive-first with decisive mutants before ${mode} fixture inventory`);
    }
    return true;
  };
  const expectDescriptorOrderFailure = (mutant, mode, label) => {
    let reason = '';
    try { requireDescriptorOrder(mutant); } catch (error) { reason = String(error?.message ?? error); }
    const expected = `descriptor controls must run positive-first with decisive mutants before ${mode} fixture inventory`;
    if (reason !== expected) throw new Error(`descriptor control source self-test missed ${label}: ${reason || 'accepted'}`);
  };
  // Validate the unmodified, complete actual caller before testing branch-bound mutations.
  requireDescriptorOrder(verifier);
  for (const [mode] of descriptorBranchSpec) {
    const descriptorPositive = "executeInventory(binary, ['TestPlanBrokerCPUDescriptorGuardControls'], 60, false);";
    const descriptorNegative = `verifyCompiledDescriptorGuardMutants(temp, '${mode}');`;
    const fixture = 'const output = executeInventory(binary, selected, 240, true);';
    const missingPositive = mutateActualDescriptorBranch(verifier, mode, (branch) => {
      if (branch.split(descriptorPositive).length !== 2) throw new Error(`actual descriptor positive call anchor is not unique: ${mode}`);
      return branch.replace(descriptorPositive, '// omitted actual descriptor positive control');
    });
    expectDescriptorOrderFailure(missingPositive, mode, `omitted ${mode} actual positive control`);
    const missingMutants = mutateActualDescriptorBranch(verifier, mode, (branch) => {
      if (branch.split(descriptorNegative).length !== 2) throw new Error(`actual descriptor mutant call anchor is not unique: ${mode}`);
      return branch.replace(descriptorNegative, '// omitted actual descriptor mutants');
    });
    expectDescriptorOrderFailure(missingMutants, mode, `omitted ${mode} compiled mutants`);
    const movedPositive = mutateActualDescriptorBranch(verifier, mode, (branch) => {
      if (branch.split(descriptorPositive).length !== 2 || branch.split(fixture).length !== 2) throw new Error(`actual positive/fixture anchors are not unique: ${mode}`);
      return branch.replace(descriptorPositive, '// moved actual descriptor positive control')
        .replace(fixture, `${fixture}\n      ${descriptorPositive}`);
    });
    expectDescriptorOrderFailure(movedPositive, mode, `moved ${mode} actual positive control after effectful inventory`);
  }
  const positive = [...expectedUnitHolderControlEvents.map(([name, phase]) => `__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\t${name}\t${phase}`), `${unitHolderMatrixEventPrefix} cases=10 budget_ms=45000 worker_ms=90000 reserve_ms=40000 elapsed_ms=12000 worker_remaining_ms=70000`].join('\n');
  validateUnitHolderControlEvents(positive);
  const rejectEvent = (mutant, label) => {
    let rejected = false;
    try { validateUnitHolderControlEvents(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`holder transcript parser accepted ${label} mutant`);
  };
  rejectEvent(positive.replace('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_close_boundary\tclose\n', ''), 'missing case');
  rejectEvent(positive.replace('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_close_boundary\tclose', '__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_close_boundary\timport'), 'wrong phase');
  rejectEvent(positive.replace('budget_ms=45000', 'budget_ms=90000'), 'expanded aggregate budget');
  rejectEvent(positive.replace('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\twatchdog_native_expiry\tpre_ready\n', ''), 'missing watchdog control');
  rejectEvent(positive.replace('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_method_boundary\tmethod\n', ''), 'missing actual method-boundary control');
  rejectEvent(positive.replace('__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_import_boundary\timport\n', '') + '\n__PLAN_RELAUNCH_UNIT_HOLDER_CONTROL__\tparentdeath_import_boundary\timport', 'out-of-order duplicate');
  rejectEvent(positive.replace('worker_remaining_ms=70000', 'worker_remaining_ms=10000'), 'missing post-matrix worker reserve');
  rejectEvent(positive.replace('elapsed_ms=12000', 'elapsed_ms=50000'), 'overrun aggregate wall ceiling');
  const reject = (mutant, label) => {
    let failed = false;
    try { validateUnitHolderControlSource(mutant); } catch { failed = true; }
    if (!failed) throw new Error(`holder-control source predicate accepted ${label} mutant`);
  };
  const mutateCapWait = (before, after) => {
    const start = source.indexOf('def cap_terminal_wait():');
    const end = source.indexOf('\ndef send_reply(frame):', start);
    if (start < 0 || end <= start) throw new Error('cap wait mutation region is missing');
    const region = source.slice(start, end);
    if (region.split(before).length !== 2) throw new Error('cap wait mutation anchor is not unique');
    return source.slice(0, start) + region.replace(before, after) + source.slice(end);
  };
  reject(source.replace("'parentdeath_close_boundary':('close',True),", ''), 'missing fixed case');
  reject(source.replace("raw_control=os.read(CONTROL,80)", "raw_control=os.read(CONTROL,800)"), 'unbounded selector read');
  reject(source.replace('else: die(131)', 'else: pass'), 'unknown case bypass');
  reject(source.replace("'negative_ref_error':'ref_error',", ''), 'missing injected RefUnit negative case');
  reject(source.replace("'negative_watchdog_omitted':'watchdog_omitted',", ''), 'missing watchdog omission negative case');
  reject(source.replace('time.sleep(30.0)', 'while True:\n                time.sleep(0.1)'), 'unbounded watchdog-omission loop');
  reject(source.replace('if isPlanBrokerCPUInjectedRefError(err) {', 'if false {'), 'normal acquisition ignores injected RefUnit error');
  reject(source.replace('if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {\n\t\tcontrolDeadline :=', 'if false {\n\t\tcontrolDeadline :='), 'watchdog case bypasses held-parent oracle');
  if (source.includes('os.Getenv(planBrokerCPUNegativeControlEnv)')) throw new Error('holder negative control must not be selected by process environment');
  reject(source.replace('if target == "startup" {', 'if target == "unknown" {'), 'missing startup identity phase');
  reject(source.replace("Manager','RefUnit','s',(unit,)", "Manager','RefUnit','ss',(unit,'replace')"), 'incorrect systemd RefUnit signature');
  reject(source.replace('return min(2.0,phase_remaining())', 'return 2.0'), 'method timeout ignores phase remaining');
  reject(source.replace('for index := 0; index < 3; index++ {', 'for index := 0; index < 0; index++ {'), 'shortened-cap case omits actual health progress');
  reject(source.replace('if health_cycles==3:', 'if health_cycles==2:'), 'absolute-cap alarm arms before three completed health cycles');
  reject(source.replace('signal.setitimer(signal.ITIMER_REAL,remaining,0.0)', 'signal.setitimer(signal.ITIMER_REAL,remaining+1.0,0.0)'), 'absolute-cap timer exceeds its immutable deadline');
  reject(source.replace('if left>0 and timer[0]<=0.0: die(162)', 'if False: die(162)'), 'cap wait accepts a disabled native timer before the absolute deadline');
  reject(source.replace('if timer[1]!=0.0: die(161)', 'if timer[1]<0.0: die(161)'), 'cap wait accepts a periodic native alarm');
  reject(source.replace("if phase=='cap_terminal':\n                cap_terminal_wait()\n                continue", "if phase=='cap_terminal':\n                guard_check(True)\n                cap_terminal_wait()\n                continue"), 'cap wait re-enters competing manual deadline/rearm logic');
  reject(mutateCapWait('poller.register(PARENT,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)', 'poller.register(PARENT,select.POLLIN)'), 'cap wait loses parent pidfd terminal/error monitoring');
  reject(mutateCapWait('poller.register(GUARD,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)', 'poller.register(GUARD,select.POLLIN)'), 'cap wait loses guard EOF/error monitoring');
  reject(source.replace("if block:\n        part=os.read(BLOCK,1)", "if False:\n        part=os.read(BLOCK,1)"), 'nonblocking synthetic boundary');
  reject(source.replace('planBrokerCPUHolderControlAggregateBudget = 45 * time.Second', 'planBrokerCPUHolderControlAggregateBudget = 95 * time.Second'), 'expanded matrix budget');
  reject(source.replace('runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)', '/* omitted control matrix */'), 'omitted pre-stop matrix');
  reject(source.replace('transcriptBytes > 1024', 'transcriptBytes > 4096'), 'expanded transcript bound');
  reject(source.replace('cmd.Stdout = os.Stdout', 'cmd.Stderr = os.Stdout'), 'missing late-proof stdout forwarding');
  reject(source.replace('if control == planBrokerCPUControlAfterRearmDeath {\n\t\tcmd.Stdout = os.Stdout\n\t}', 'if control != planBrokerCPUControlAfterRearmDeath {\n\t\tcmd.Stdout = os.Stdout\n\t}'), 'stdout forwarding broadened outside the one owned case');
  reject(source.replace('if err := requireReportEOF(terminalDeadline, planBrokerCPUReasonPipe); err != nil { return failure(planBrokerCPUReasonPipe, err) }', ''), 'late report EOF proof omitted');
  reject(source.replace('reader.bytes+frameSize > 1024', 'reader.bytes+frameSize > 8192'), 'report aggregate cap expanded');
  reject(source.replace('frameSize > 192 || reader.bytes+frameSize > 1024', 'frameSize > 8192 || reader.bytes+frameSize > 1024'), 'report frame cap expanded');
  reject(source.replace('if len(reader.buffer) != 0 { return errors.New("fixed control report contains an unexpected queued or duplicate record") }', ''), 'queued duplicate record accepted');
  reject(source.replace('if n != 0 { return errors.New("fixed control report contains an unexpected trailing or duplicate byte") }', ''), 'trailing duplicate report accepted');
  reject(source.replace('fmt.Println(planBrokerCPUHolderOmittedDefinitionPredicate)', ''), 'omitted-retention intended predicate not emitted');
  reject(source.replace('if err != nil && code == "unit_definition_missing" {', 'if err != nil {'), 'omitted-retention predicate emitted for an unclassified stop error');
  reject(source.replace('if waitCode != "unit_definition_missing" {', 'if false {'), 'early-release predicate emitted for a non-missing-definition outcome');
  reject(source.replace('if closeErr := holder.closeFiles(); closeErr != nil { return errors.New("guard-EOF rejection descriptor custody close was uncertain") }', ''), 'EOF-alive marker emitted without successful close custody');
  reject(source.replace('if holder.guard == nil {\n\t\t// The closed-sole-writer case must await the existing Wait owner. Do not\n\t\t// route this intentional terminal through the live-helper assertion.\n\t\treturn waitExactTerminal()\n\t}', 'if holder.guard == nil { return nil }'), 'closed-writer phase skips its sole Wait owner');
  reject(source.replace('case <-time.After(remaining):\n\t\t\treturn errors.New("guard-EOF helper Wait did not settle within its original absolute terminal deadline")', 'case <-time.After(5 * time.Second):\n\t\t\treturn errors.New("guard-EOF helper Wait did not settle within its original absolute terminal deadline")'), 'EOF wait creates a fresh terminal deadline');
  reject(source.replace('// A pidfd terminal can precede publication by the sole Wait owner.\n\t\t\t// Give that owner only the residual time from the original deadline.\n\t\t\treturn waitExactTerminal()', 'return errors.New("pidfd terminal was not joined")'), 'live terminal race skips the sole Wait result');
  reject(source.replace('transcriptBytes+lateProofBytes > 1024', 'false'), 'late proof bytes omitted from the combined holder cap');
  reject(source.replace('transcriptBytes+lateProofBytes > 1024', 'transcriptBytes+lateProofBytes > 2048'), 'combined holder byte cap widened');
  reject(source.replace('holder.requireStatusEOFUntil(deadline)', 'nil'), 'normal release EOF read not bounded');
  reject(source.replace('*file = nil', '*file = *file'), 'owned file pointer not detached after close');
  const holderType = uniqueSourceRegion(source, 'type planBrokerCPUUnitHolder struct {', 'type planBrokerCPUHolderControl string');
  if (!holderType.includes('abortDone') || !holderType.includes('abortErr') || !holderType.includes('closeErr') || !holderType.includes('releaseDone') || !holderType.includes('releaseErr')) throw new Error('holder lifecycle must latch the one abort, release and close outcome');
  const abort = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) abort() error {', '\nfunc (holder *planBrokerCPUUnitHolder) closeFiles()');
  if (!abort.includes('if holder.abortDone { return holder.abortErr }') || !abort.includes('deadline := time.Now().Add(5 * time.Second)') || (abort.match(/time\.After\(5\s*\*\s*time\.Second\)/g) ?? []).length !== 0 || !abort.includes('holder.abortErr = errors.Join(result, holder.closeFiles())')) throw new Error('abort must latch failure and use one total five-second settlement deadline');
  const release = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) release() error {', '\nfunc (holder *planBrokerCPUUnitHolder) abort()');
  if (!release.includes('holder.requireStatusEOFUntil(deadline)')) throw new Error('normal release must use the original absolute phase deadline for exact EOF');
  const statusEOF = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) requireStatusEOFUntil(', '\nfunc (holder *planBrokerCPUUnitHolder) abort()');
  if (!statusEOF.includes('unix.Poll(poll, ms)') || !statusEOF.includes('holder.status.Read(trailing[:])') || !statusEOF.includes('errors.Is(readErr, io.EOF)') || !statusEOF.includes('time.Now().Before(deadline)')) throw new Error('normal release final EOF read must be readiness-polled and bounded by the same deadline');
  const closeFiles = uniqueSourceRegion(source, 'func (holder *planBrokerCPUUnitHolder) closeFiles() error {', '\nfunc planBrokerCPUHolderIdentityCurrent(');
  if (!closeFiles.includes('if holder.closed { return holder.closeErr }') || !closeFiles.includes('holder.closeErr = result') || !closeFiles.includes('*file = nil') || !closeFiles.includes('holder.childPIDFD = -1')) throw new Error('descriptor close uncertainty must remain latched and owned descriptors detached after their one close');
  return true;
}

function sourceOnlyControls() {
  const policy = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_plan_rotation.go'), 'utf8');
  const policyTest = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_plan_rotation_test.go'), 'utf8');
  const broker = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_lifecycle_broker_linux.go'), 'utf8');
  const brokerTest = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_lifecycle_broker_linux_test.go'), 'utf8');
  const cpuFixture = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go'), 'utf8');
  const verifier = readFileSync(fileURLToPath(import.meta.url), 'utf8');

  selfTestExpectedFailureClassifier();
  selfTestDescriptorGuardControlResult();
  selfTestTypedFailureStageSource(verifier, cpuFixture);
  selfTestPureDiagnosticControlSource(verifier, cpuFixture);
  selfTestFailureMarkerControlSource(cpuFixture);
  selfTestFixedRootTransportSource(verifier);
  selfTestCPUFixtureTreeSource(cpuFixture);
  selfTestTransport12Source(cpuFixture);
  selfTestStoppedStateProofSource(broker, brokerTest, cpuFixture);
  selfTestTransport14InactiveWaitSource(cpuFixture);
  selfTestUnitHolderControlSource(cpuFixture, verifier);
  selfTestTransport14FailureClassifier(verifier);
  selfTestOptInTestFailureSites(verifier);
  validateBrokerRequestTransportSource(broker, brokerTest, verifier);

  const freeze = readCurrentFreeze();
  validateFreezeManifest(freeze, false);
  const rejectFreeze = (mutant, expectedCode, requireReview = false) => {
    let reason = '';
    try { validateFreezeManifest(mutant, requireReview); } catch (error) { reason = String(error?.message ?? error); }
    if (!reason.includes(`freeze:${expectedCode}`)) throw new Error(`freeze source control failed to reject ${expectedCode}: ${reason || 'accepted'}`);
  };
  rejectFreeze({ ...freeze, files: freeze.files.slice(1) }, 'missing-path');
  rejectFreeze({ ...freeze, files: [...freeze.files, { ...freeze.files[0] }] }, 'duplicate-path');
  rejectFreeze({ ...freeze, files: [...freeze.files, { ...freeze.files[0], Path: 'internal/nodeagent/unowned.go' }] }, 'extra-path');
  rejectFreeze({ ...freeze, files: freeze.files.map((entry, index) => index === 0 ? { ...entry, Path: 'internal/nodeagent/substitute.go' } : entry) }, 'substitute-path');
  rejectFreeze({ ...freeze, files: freeze.files.map((entry, index) => index === 0 ? { ...entry, Bytes: entry.Bytes + 1 } : entry) }, 'stale-pin');
  rejectFreeze({ ...freeze, reviewStatus: 'pending-root-review' }, 'not-root-reviewed', true);
  const validateEnabledPreflightSource = (source) => {
    const region = uniqueSourceRegion(source, 'function withPrivateBinary(mode) {', 'const recoveryPolicyTests =');
    const reviewCheckAt = region.indexOf('requireReviewedCurrentFreeze();');
    const tempCreationAt = region.indexOf('mkdtempSync(');
    const compilerAt = region.indexOf('compileLinuxBinary(');
    const executionAt = region.indexOf('executeInventory(');
    if (reviewCheckAt < 0 || tempCreationAt <= reviewCheckAt || (compilerAt >= 0 && compilerAt <= reviewCheckAt) || (executionAt >= 0 && executionAt <= reviewCheckAt)) throw new Error('enabled-mode exact-pin/root-review preflight must precede every private workspace or compiler effect');
    return true;
  };
  validateEnabledPreflightSource(verifier);
  const earlyTempMutant = verifier.replace(
    "function withPrivateBinary(mode) {\n  requireReviewedCurrentFreeze();\n  const prefix = '.tmp-plan-relaunch-verifier-';\n  const temp = mkdtempSync(path.join(root, prefix));",
    "function withPrivateBinary(mode) {\n  const prefix = '.tmp-plan-relaunch-verifier-';\n  const temp = mkdtempSync(path.join(root, prefix));\n  requireReviewedCurrentFreeze();",
  );
  if (earlyTempMutant === verifier) throw new Error('early-temp preflight mutant anchor is not exact');
  let earlyTempRejected = false;
  try { validateEnabledPreflightSource(earlyTempMutant); } catch { earlyTempRejected = true; }
  if (!earlyTempRejected) throw new Error('enabled-mode source controls accepted temporary workspace creation before root-reviewed exact pins');
  const sourceDispatchAt = verifier.indexOf("if (argv[0] === '--mode=source-only') {");
  const sourceExitAt = verifier.indexOf('process.exit(0);', sourceDispatchAt);
  if (sourceDispatchAt < 0 || sourceExitAt < 0 || sourceExitAt > verifier.indexOf('withPrivateBinary(argv[0]);')) throw new Error('source-only mode must complete before enabled-mode preflight or effects');

  const expectedPortable = ['TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart'];
  for (const name of expectedPortable) {
    if (!policyTest.includes(`func ${name}(t *testing.T) {`)) throw new Error(`selected recovery policy regression is missing: ${name}`);
  }
  const catalogName = 'TestCheckpointPlanCatalogRequiresCanonicalApprovedV2Bytes';
  const catalogTest = uniqueSourceRegion(brokerTest, `func ${catalogName}(t *testing.T) {`, 'type planBrokerRequestFaultConn struct {');
  const catalogFixture = uniqueSourceRegion(brokerTest, 'type checkpointCatalogFixtureObject struct {', `func ${catalogName}(t *testing.T) {`);
  const validateCatalogFixtureSource = (testSource, fixtureSource) => {
    const requiredTest = ['decodeCheckpointPlanCatalog(raw, fixture.paths)', 'decodeCheckpointPlanCatalog(raw); err == nil', 'checkpointPlanBrokerPrivateFixturePathSet(fixture.paths)', 'parseCatalogPlanBytes(t, mutant)', 'PlanSHA256: sha256Hex(encoded)', 'PlanBase64: base64.StdEncoding.EncodeToString(encoded)', 'ParseCheckpointLaunchPlan(decoded)', 'missing model', 'missing executable', 'symlink model', 'symlink executable', 'nonExecutableParserControl(t)', 'fixture.cleanup()'];
    for (const required of requiredTest) if (!testSource.includes(required)) throw new Error(`catalog positive, parser negative, or fixed-root control is missing: ${required}`);
    const positiveAt = testSource.indexOf('decodeCheckpointPlanCatalog(raw, fixture.paths)');
    const negativeAt = testSource.indexOf('missingModel := fixture.plan');
    if (positiveAt < 0 || negativeAt <= positiveAt) throw new Error('catalog parser filesystem negatives must follow the real positive decoder case');
    for (const label of ['missing model', 'missing executable', 'symlink model', 'symlink executable', 'nonExecutableParserControl(t)']) {
      const at = testSource.indexOf(label, positiveAt);
      if (at <= positiveAt) throw new Error(`catalog filesystem parser control is missing or precedes its positive: ${label}`);
    }
    for (const required of ['os.Geteuid() != 0', 't.Setenv("VRAM_PLAN_BROKER_CPU_OPT_IN", "I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS")', 'user.LookupId("65534")', 'os.SameFile(item.info, current)', 'os.Remove(item.path)', 'os.IsNotExist(err)', 'os.ReadDir(item.path)', 'checkpointPlacementFixture()', 'os.OpenFile(file.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL', 'os.Symlink(alias.target, alias.path)', 'os.Chmod(file.path, file.mode)', 'cleanupAttempted', 'cleanupOutcome', 'f.cleanupAttempted = true', 'f.preserve', 'allowSymlink', 'nonExecutableParserControl', 'f.workerInfo', 'f.workerMode', 'os.Chmod(f.workerPath, f.workerMode)']) if (!fixtureSource.includes(required)) throw new Error(`catalog fixture boundary or exact cleanup is missing: ${required}`);
    if (fixtureSource.includes('os.RemoveAll') || fixtureSource.includes('MkdirAll') || fixtureSource.includes('fixedCheckpointPlanBrokerPaths().RuntimeDir')) throw new Error('catalog fixture must use its exact private path set and nonrecursive identity-held cleanup');
    if (fixtureSource.includes('defer func()') || !fixtureSource.includes('t.Cleanup(func()') || !fixtureSource.includes('if !fixture.cleanupAttempted {')) throw new Error('catalog fixture cleanup must have one latched cleanup owner, not a retrying defer');
    const cleanupAttemptedAt = fixtureSource.indexOf('f.cleanupAttempted = true');
    const firstRemoveAt = fixtureSource.indexOf('os.Remove(item.path)');
    if (!fixtureSource.includes('if f.cleanupAttempted {') || !fixtureSource.includes('return f.cleanupOutcome') || cleanupAttemptedAt < 0 || firstRemoveAt <= cleanupAttemptedAt) throw new Error('catalog cleanup must latch one attempt before any removal and return the latched outcome');
    const restoreStart = fixtureSource.indexOf('func (f *checkpointCatalogFixture) nonExecutableParserControl(');
    const restoreEnd = fixtureSource.indexOf('\nfunc parseCatalogPlanBytes(', restoreStart);
    const restoreRegion = restoreStart < 0 || restoreEnd <= restoreStart ? '' : fixtureSource.slice(restoreStart, restoreEnd);
    for (const required of ['os.SameFile(f.workerInfo, held)', 'f.workerMode.Perm()&^0o111', 'ParseCheckpointLaunchPlan(decodedPlan)', 'os.SameFile(f.workerInfo, restored)', 'restored.Mode().Perm() != f.workerMode.Perm()', 'f.preserve = true']) if (!restoreRegion.includes(required)) throw new Error(`non-executable mutation does not safely restore the held worker inode: ${required}`);
    return true;
  };
  validateCatalogFixtureSource(catalogTest, catalogFixture);
  const mutateExactlyOnce = (source, needle, replacement) => {
    if (source.split(needle).length !== 2) throw new Error(`catalog control anchor is not exact once: ${needle}`);
    return source.replace(needle, replacement);
  };
  for (const [region, needle, replacement] of [
    ['test', 'checkpointPlanBrokerPrivateFixturePathSet(fixture.paths)', 'true'],
    ['fixture', 'os.SameFile(item.info, current)', 'false'],
    ['fixture', 'os.Remove(item.path)', 'os.RemoveAll(item.path)'],
    ['fixture', 'if f.cleanupAttempted {', 'if false {'],
  ]) {
    const mutantTest = region === 'test' ? mutateExactlyOnce(catalogTest, needle, replacement) : catalogTest;
    const mutantFixture = region === 'fixture' ? mutateExactlyOnce(catalogFixture, needle, replacement) : catalogFixture;
    let rejected = false;
    try { validateCatalogFixtureSource(mutantTest, mutantFixture); } catch { rejected = true; }
    if (!rejected) throw new Error(`catalog fixture source control accepted removal of ${needle}`);
  }
  const crashJournal = uniqueSourceRegion(cpuFixture, 'func TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect(t *testing.T) {', 'func TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {');
  const validateCrashJournalLinkage = (source) => {
    for (const required of ['rejectDuplicateJSONKeys(step.OriginalEnvelope)', 'wsproto.ValidatePlanRelaunchCommandArgs(durableUrgent.Command, durableUrgent.Args)', 'wsproto.CanonicalCommandEnvelope(durableUrgent)', 'bytes.Equal(step.OriginalEnvelope, wire)', 'step.EnvelopeSHA256 != sha256Hex(step.OriginalEnvelope)', '"prior_command_id"', '"prior_idempotency_key"', '"prior_receipt_sha256"', 'priorCommand.ID', 'priorCommand.IdempotencyKey', 'sha256Hex(victimStopReceipt)']) if (!source.includes(required)) throw new Error(`durable urgent command linkage is incomplete: ${required}`);
    if (source.includes('operation.Operation.Steps["victim_stop"]') || source.includes('operation.Operation.PriorReceiptSHA256')) throw new Error('journal linkage must not assume fields absent from the immutable operation template');
    return true;
  };
  validateCrashJournalLinkage(crashJournal);
  let stalePriorFieldRejected = false;
  try { validateCrashJournalLinkage(`${crashJournal}\noperation.Operation.PriorReceiptSHA256`); } catch { stalePriorFieldRejected = true; }
  if (!stalePriorFieldRejected) throw new Error('durable journal source control accepted the stale nonexistent PriorReceiptSHA256 member');
  for (const required of ['bytes.Equal(step.OriginalEnvelope, wire)', '"prior_command_id"', '"prior_idempotency_key"', '"prior_receipt_sha256"']) {
    const mutant = crashJournal.replace(required, '"removed_linkage"');
    let rejected = false;
    try { validateCrashJournalLinkage(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`durable urgent command source control accepted removal of ${required}`);
  }
  const issue = declarationBody(policy, 'func checkpointPlanRelaunchMayIssueFirstStart(step, stage string) bool {', 'func checkpointPlanRelaunchMayJoinStartedProcess(step, stage string) bool {');
  const join = declarationBody(policy, 'func checkpointPlanRelaunchMayJoinStartedProcess(step, stage string) bool {', 'func checkpointPlanRelaunchIsCommand(command string) bool {');
  if (!issue.includes('stage == step+"_published"') || issue.includes('stage == step+"_start_requested"')) throw new Error('first-start policy no longer limits dispatch to the durable published stage');
  if (!join.includes('stage == step+"_start_requested" || stage == step+"_start_accepted"') || join.includes('stage == step+"_published"')) throw new Error('live-process join policy admits a pre-start stage or omits accepted start state');
  const recovery = declarationBody(broker, 'func reconcileCheckpointPlanBrokerPending(ctx context.Context, paths checkpointPlanBrokerPaths, cfg *Config, state commandStatePayload, operation checkpointPlanRelaunchOperation, entry checkpointPlanBrokerOperation, stepID string, nodeStep checkpointPlanRelaunchStep, rootStep checkpointPlanRelaunchStep) (checkpointPlanBrokerResponse, error) {', 'func ');
  if (!recovery.includes('checkpointPlanRelaunchMayIssueFirstStart(stepID, entry.Stage)') || !recovery.includes('checkpointPlanRelaunchMayJoinStartedProcess(stepID, entry.Stage)')) throw new Error('production recovery no longer enforces both stage-authority guards');
  const noStartMutant = recovery.replace('checkpointPlanRelaunchMayIssueFirstStart(stepID, entry.Stage)', 'true');
  const noJoinMutant = recovery.replace('checkpointPlanRelaunchMayJoinStartedProcess(stepID, entry.Stage)', 'true');
  if (noStartMutant.includes('checkpointPlanRelaunchMayIssueFirstStart(stepID, entry.Stage)') || noJoinMutant.includes('checkpointPlanRelaunchMayJoinStartedProcess(stepID, entry.Stage)')) throw new Error('source mutation controls failed to remove the production guard anchors');
  const faultBlock = cpuFixture.slice(cpuFixture.indexOf('faultStages := []string{'), cpuFixture.indexOf('\n\tvar faultIndex', cpuFixture.indexOf('faultStages := []string{')));
  if (!cpuFixture.includes('durable start_requested boundary remains excluded') || !cpuFixture.includes('separate tagged crash/no-effect oracle below') || faultBlock.includes('"start_requested_durable"')) throw new Error('auto-reconverging matrix must disclose, but not absorb, the ambiguous crash window');
  const crashTestName = 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect';
  const crashStart = cpuFixture.indexOf(`\nfunc ${crashTestName}(t *testing.T) {`);
  const crashEnd = cpuFixture.indexOf('\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {', crashStart);
  if (crashStart < 0 || crashEnd <= crashStart || cpuFixture.indexOf(`\nfunc ${crashTestName}(t *testing.T) {`, crashStart + 1) >= 0) throw new Error('separate start-request crash oracle declaration is missing or ambiguous');
  const crashTest = cpuFixture.slice(crashStart, crashEnd);
  for (const required of ['startPlanBrokerCPUBroker(workerExecutable, paths, "start_requested_durable")', 'operation.Stage != "urgent_load_start_requested"', 'attempt := 1; attempt <= 2', '__PLAN_RELAUNCH_CPU_UNCERTAIN__', 'ambiguous start recovery changed unit/MainPID']) {
    if (!crashTest.includes(required)) throw new Error(`start-request crash oracle source is missing a decisive control: ${required}`);
  }
  const validateParentGuardSource = (source) => {
    const guardedStart = source.indexOf('\nfunc startPlanBrokerCPUGuardedChild(cmd *exec.Cmd) (*os.File, error) {');
    const guardedEnd = source.indexOf('\nfunc stopPlanBrokerCPUStartedChild(', guardedStart);
    const armStart = source.indexOf('\nfunc armPlanBrokerCPUParentGuard() (context.Context, func(), error) {');
    const armEnd = source.indexOf('\nfunc capturePlanBrokerCPUProcessIdentity(', armStart);
    const oracleStart = source.indexOf('\nfunc runPlanBrokerCPUParentDeathOracle(worker string, paths checkpointPlanBrokerPaths, rootInfo os.FileInfo, gid uint32) (result error) {');
    const oracleEnd = source.indexOf('\nfunc startPlanBrokerCPUGuardedChild(', oracleStart);
    const helperStart = source.indexOf('\nfunc runPlanBrokerCPUParentDeathHelper(t *testing.T) {');
    const helperEnd = source.indexOf('\nfunc holdPlanBrokerCPUPIDFD(', helperStart);
    const targetStart = source.indexOf('\nfunc planBrokerCPUPIDFDTarget(pidfd int) (int, error) {');
    const targetEnd = source.indexOf('\nfunc holdPlanBrokerCPUPIDFD(', targetStart);
    const holdStart = source.indexOf('\nfunc holdPlanBrokerCPUPIDFD(identity planBrokerCPUProcessIdentity) (int, error) {');
    const holdEnd = source.indexOf('\nfunc runPlanBrokerCPUParentDeathOracle(', holdStart);
    if ([guardedStart, armStart, oracleStart, helperStart, targetStart, holdStart].some((index) => index < 0) || guardedEnd <= guardedStart || armEnd <= armStart || oracleEnd <= oracleStart || helperEnd <= helperStart || targetEnd <= targetStart || holdEnd <= holdStart) throw new Error('parent-death source declarations are missing or ambiguous');
    const guarded = source.slice(guardedStart, guardedEnd);
    const arm = source.slice(armStart, armEnd);
    const oracle = source.slice(oracleStart, oracleEnd);
    const helper = source.slice(helperStart, helperEnd);
    const target = source.slice(targetStart, targetEnd);
    const hold = source.slice(holdStart, holdEnd);
    const requiredGuarded = ['os.Pipe()', 'cmd.ExtraFiles = []*os.File{guardRead, readyWrite}', 'guardRead.Close()', "guardWrite.Write([]byte{'P'})", '"READY\\n"', 'time.After(5 * time.Second)'];
    const requiredArm = ['os.NewFile(3,', 'os.NewFile(4,', "token[0] != 'P'", 'watcherStarted := make(chan struct{})', 'close(watcherStarted)', '<-watcherStarted', 'guardRead.Read(extra[:])', 'errors.Is(err, io.EOF)', 'cancel()', 'readyWrite.Write([]byte("READY\\n"))'];
    const requiredOracle = ['parentPIDFD := -1', 'cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}', 'cmd.Start()', 'parentWaitResult := make(chan error, 1)', 'parentWaitStarted := false', 'if parentWaitStarted {', 'parentWaitStarted = true', 'go func() { parentWaitResult <- cmd.Wait() }()', 'closeUnboundParentPIDFD := func() error {', 'abortUnboundParent := func(primary error) error {', 'errors.Join(readyRead.Close(), readyWrite.Close())', 'startParentWait()', 'case waitErr := <-parentWaitResult:', 'case <-time.After(5 * time.Second):', 'closeUnboundParentPIDFD()', 'unbound parent helper was reaped after failed spawn binding; preserving fixture without custody proof', 'unbound parent helper did not settle within fixed 5s; preserving fixture with custody uncertainty', 'errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, primary), closeErr, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, waitErr)', 'planBrokerCPUPIDFDTarget(parentPIDFD)', 'parentTarget != cmd.Process.Pid', 'capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)', 'unix.PidfdSendSignal(parentPIDFD, 0, nil, 0)', 'parentTarget != parentIdentity.PID', 'holdPlanBrokerCPUPIDFD(report.Broker)', 'holdPlanBrokerCPUPIDFD(report.Unrelated)', 'stopExactParent()', 'verifyPlanBrokerCPUProcessIdentity(parentIdentity)', 'planBrokerCPUPIDFDReady(parentPIDFD, 0)', 'unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)', 'planBrokerCPUPIDFDReady(parentPIDFD, 5*time.Second)', 'unix.Close(parentPIDFD)', 'planBrokerCPUPIDFDReady(child.pidfd, remaining)', 'unix.PidfdSendSignal(child.pidfd, syscall.SIGKILL, nil, 0)', 'errors.Join(result,', 'result = &planBrokerCPUSurvivorPredicateFailure{err: result}', 'preserving fixture'];
    const requiredTarget = ['os.Open(filepath.Join("/proc/self/fdinfo", strconv.Itoa(pidfd)))', 'io.LimitReader(file, 4097)', 'len(data) > 4096', 'strings.HasPrefix(line, "Pid:")', 'target != -1', 'parsed, parseErr := strconv.Atoi', 'parseErr != nil || parsed <= 1', 'if target <= 1', 'return target, nil'];
    const requiredHold = ['verifyPlanBrokerCPUProcessIdentity(identity)', 'unix.PidfdOpen(identity.PID, 0)', 'planBrokerCPUPIDFDReady(pidfd, 0)', 'unix.PidfdSendSignal(pidfd, 0, nil, 0)'];
    const requiredHelper = ['makePlanBrokerCPUUnrelatedChild(&unrelated, worker, root, uint32(gid))', 'startPlanBrokerCPUBroker(worker, paths)', 'capturePlanBrokerCPUProcessIdentity(broker.cmd.Process.Pid)', 'capturePlanBrokerCPUProcessIdentity(unrelated.cmd.Process.Pid)', 'json.Marshal(report)', 'len(encoded) > 2048', 'readyWrite.Write(append(encoded, \'\\n\'))', 'select {}'];
    for (const required of [...requiredGuarded, ...requiredArm, ...requiredOracle, ...requiredTarget, ...requiredHelper, ...requiredHold]) {
      const region = requiredGuarded.includes(required) ? guarded : requiredArm.includes(required) ? arm : requiredOracle.includes(required) ? oracle : requiredTarget.includes(required) ? target : requiredHelper.includes(required) ? helper : hold;
      if (!region.includes(required)) throw new Error(`parent-death fixture is missing a decisive guard/oracle anchor: ${required}`);
    }
    const pidfdInitAt = oracle.indexOf('parentPIDFD := -1');
    const sysProcAttrAt = oracle.indexOf('cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}');
    const startAt = oracle.indexOf('if err := cmd.Start(); err != nil {');
    const targetAt = oracle.indexOf('parentTarget, targetErr := planBrokerCPUPIDFDTarget(parentPIDFD)');
    const targetCompareAt = oracle.indexOf('parentTarget != cmd.Process.Pid');
    const identityAt = oracle.indexOf('parentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)');
    const signalZeroAt = oracle.indexOf('unix.PidfdSendSignal(parentPIDFD, 0, nil, 0)');
    const targetAgainAt = oracle.indexOf('parentTarget, targetErr = planBrokerCPUPIDFDTarget(parentPIDFD)', targetAt + 1);
    const abortStart = oracle.indexOf('\tabortUnboundParent := func(primary error) error {');
    const abortEnd = oracle.indexOf('\n\tparentTarget, targetErr :=', abortStart);
    const abort = oracle.slice(abortStart, abortEnd);
    const abortWaitAt = abort.indexOf('startParentWait()');
    const abortSelectAt = abort.indexOf('select {');
    const abortBoundedAt = abort.indexOf('case <-time.After(5 * time.Second):');
    const ownerAt = oracle.indexOf('go func() { parentWaitResult <- cmd.Wait() }()');
    const ownerHelperStart = oracle.indexOf('\tstartParentWait := func() {');
    const ownerHelperEnd = oracle.indexOf('\n\tcloseUnboundParentPIDFD :=', ownerHelperStart);
    const waitAt = oracle.indexOf('\tstartParentWait()\n\tparentWaited := false', targetAgainAt);
    if (!(pidfdInitAt >= 0 && sysProcAttrAt > pidfdInitAt && startAt > sysProcAttrAt && targetAt > startAt && targetCompareAt > targetAt && identityAt > targetCompareAt && signalZeroAt > identityAt && targetAgainAt > signalZeroAt && waitAt > targetAgainAt) || (oracle.match(/parentPIDFD\s*:=/g) ?? []).length !== 1 || oracle.includes('holdPlanBrokerCPUPIDFD(parentIdentity)') || oracle.includes('unix.PidfdOpen(') || (oracle.match(/cmd\.Wait\(\)/g) ?? []).length !== 1 || ownerHelperStart < 0 || ownerHelperEnd <= ownerHelperStart || ownerAt < ownerHelperStart || ownerAt >= ownerHelperEnd || abortStart < 0 || abortEnd <= abortStart || abortWaitAt < 0 || abortSelectAt <= abortWaitAt || abortBoundedAt <= abortSelectAt || abort.indexOf('case waitErr := <-parentWaitResult:') <= abortSelectAt || !abort.includes('closeUnboundParentPIDFD()') || abort.includes('cmd.Wait()') || !abort.includes('errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, primary), closeErr, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, waitErr)') || !abort.includes('unbound parent helper did not settle within fixed 5s; preserving fixture with custody uncertainty')) throw new Error('parent helper must preserve atomic custody, use one Wait owner, and bound failed-spawn settlement to five seconds without granting cleanup credit');
    if (hold.split('verifyPlanBrokerCPUProcessIdentity(identity)').length !== 3) throw new Error('pidfd custody must recheck the exact process identity both before and after pidfd acquisition');
    if (oracle.includes('cmd.Process.Kill()') || !oracle.includes('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)')) throw new Error('parent cleanup must use only its held pidfd, never a numeric process kill');
    if (!oracle.includes('deferred exact child pidfd signal failed; preserving fixture') || !oracle.includes('deferred exact child pidfd wait was not confirmed; preserving fixture') || !oracle.includes('deferred child pidfd close failed; preserving fixture')) throw new Error('parent-oracle cleanup errors are not surfaced as fixture uncertainty');
    const survivorPredicateAt = oracle.indexOf('result.Error() == "a direct child survived exact parent death and required pidfd-only emergency cleanup"');
    const survivorWrapperAt = oracle.indexOf('result = &planBrokerCPUSurvivorPredicateFailure{err: result}');
    const parentDeferAt = oracle.indexOf('\tdefer func() {');
    const childDeferAt = oracle.indexOf('\tdefer func() {', parentDeferAt + 1);
    if (survivorWrapperAt <= oracle.indexOf('unix.Close(parentPIDFD)') || survivorPredicateAt < 0 || !source.includes('"__PLAN_RELAUNCH_PARENT_DEATH_SURVIVOR_ASSERTED__ __PLAN_RELAUNCH_PARENT_DEATH_PIDFD_CLEANUP_PROVED__ direct child survived exact parent death and required pidfd-only cleanup"') || parentDeferAt < 0 || childDeferAt <= parentDeferAt || !oracle.slice(childDeferAt).includes('unix.Close(child.pidfd)')) throw new Error('survivor predicate cause/wrapper is not preserved and applied only after LIFO child and parent pidfd cleanup succeeds');
    const watcherStart = arm.indexOf('var extra [1]byte');
    const watcherEnd = arm.indexOf('\n\t}()', watcherStart);
    const watcher = arm.slice(watcherStart, watcherEnd);
    if (watcherStart < 0 || watcherEnd <= watcherStart || !watcher.includes('n, err := guardRead.Read(extra[:])') || !watcher.includes('if n != 0 || !errors.Is(err, io.EOF) {\n\t\t\tcancel()\n\t\t\treturn\n\t\t}\n\t\tcancel()')) throw new Error('EOF watcher does not fail closed on both EOF and unexpected parent-pipe data');
    if (oracle.indexOf('stopExactParent()') > oracle.indexOf('planBrokerCPUPIDFDReady(child.pidfd, remaining)') || oracle.indexOf('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)') < 0) throw new Error('parent-death oracle does not kill only its held exact parent before bounded child waits');
    const crashBegin = source.indexOf(`\nfunc ${crashTestName}(t *testing.T) {`);
    const crashFinish = source.indexOf('\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {', crashBegin);
    if (crashBegin < 0 || crashFinish <= crashBegin) throw new Error('parent-death oracle is not anchored in the exact tagged crash test');
    const crashBody = source.slice(crashBegin, crashFinish);
  if (!/if err := runPlanBrokerCPUParentDeathOracle\(workerExecutable, paths, rootInfo, uint32\(gid\)\); err != nil \{\s*privateOwned = false\s*for _, marker := range planBrokerCPUFailureMarkers\(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", err\) \{ fmt\.Fprintln\(os\.Stdout, marker\) \}\s*t\.Log\("__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__"\)\s*t\.Fatalf\("fixed parent-death EOF oracle failed; preserving private fixture: %v", err\)/.test(crashBody) || !crashBody.includes('t.Log("__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__")')) throw new Error('crash fixture does not execute the oracle, emit its typed failure marker, or preserve its root on uncertain failure');
    const cleanupStart = source.indexOf('\tcleanup := func() error {', crashBegin);
    const cleanupEnd = source.indexOf('\n\tdefer func() {', cleanupStart);
    const cleanup = source.slice(cleanupStart, cleanupEnd);
    if (cleanupStart < 0 || cleanupEnd <= cleanupStart || !cleanup.includes('if result == nil && privateOwned') || !cleanup.includes('private fixture identity is uncertain')) throw new Error('parent-death uncertainty does not fence private scratch deletion');
    return true;
  };
  const rejectParentGuardMutant = (mutant, label) => {
    let rejected = false;
    try { validateParentGuardSource(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`parent-death source mutant was accepted: ${label}`);
  };
  validateParentGuardSource(cpuFixture);
  const replaceExactlyOnce = (source, needle, replacement) => {
    if (source.split(needle).length !== 2) throw new Error('parent-death mutant anchor is not exact-once');
    return source.replace(needle, replacement);
  };
  const replaceInRegion = (source, startNeedle, endNeedle, needle, replacement) => {
    const start = source.indexOf(startNeedle), end = source.indexOf(endNeedle, start + startNeedle.length);
    if (start < 0 || end <= start) throw new Error('parent-death scoped mutant region is unavailable');
    const region = source.slice(start, end);
    if (region.split(needle).length !== 2) throw new Error('parent-death scoped mutant anchor is not exact-once');
    return source.slice(0, start) + region.replace(needle, replacement) + source.slice(end);
  };
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'cmd.ExtraFiles = []*os.File{guardRead, readyWrite}', 'cmd.ExtraFiles = []*os.File{guardRead, readyWrite, guardWrite}'), 'leaked-parent-writer');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'if n != 0 || !errors.Is(err, io.EOF) {', 'if false {'), 'dropped-EOF-fail-closed-check');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'guardRead.Read(extra[:])', 'n, err = 0, io.EOF'), 'omitted-EOF-watcher-read');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'if n != 0 || !errors.Is(err, io.EOF) {\n\t\t\tcancel()\n\t\t\treturn\n\t\t}\n\t\tcancel()', 'if n != 0 || !errors.Is(err, io.EOF) {\n\t\t\treturn\n\t\t}\n\t\t'), 'dropped-cancel-on-parent-eof');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'if err := verifyPlanBrokerCPUProcessIdentity(identity); err != nil {\n\t\treturn -1, err\n\t}', 'if false {\n\t\treturn -1, errors.New("mutated custody")\n\t}'), 'pidfd-open-without-precheck-of-exact-process-identity');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'privateOwned = false\n\t\tfor _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", err) { fmt.Fprintln(os.Stdout, marker) }\n\t\tt.Log("__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__")', 'for _, marker := range planBrokerCPUFailureMarkers(&failureEmission, "TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect", err) { fmt.Fprintln(os.Stdout, marker) }\n\t\tt.Log("__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__")'), 'uncertain-root-deletion-fence-removed');
  rejectParentGuardMutant(replaceInRegion(cpuFixture, 'func runPlanBrokerCPUParentDeathOracle(', '\nfunc startPlanBrokerCPUGuardedChild(', 'unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)', 'cmd.Process.Kill()'), 'numeric-parent-kill-fallback');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'result.Error() == "a direct child survived exact parent death and required pidfd-only emergency cleanup"', 'survivorObserved'), 'survivor-proof-without-cleanup-success');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, '\tcmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &parentPIDFD}\n', ''), 'parent-spawn-without-atomic-pidfd-binding');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'parentTarget != cmd.Process.Pid', 'false'), 'parent-pidfd-target-not-matched-to-spawned-child');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'errors.Join(planBrokerCPUFailureOrigin(planBrokerCPUReasonIdentity, primary), closeErr, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, waitErr), errors.New(', 'errors.Join(closeErr, planBrokerCPUFailureOrigin(planBrokerCPUReasonExit, waitErr), errors.New('), 'unbound-spawn-path-loses-primary-failure');
  const waitStatement = 'go func() { parentWaitResult <- cmd.Wait() }()';
  const withoutWait = replaceExactlyOnce(cpuFixture, waitStatement, '');
  const waitBeforeIdentity = replaceExactlyOnce(withoutWait, 'parentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)', `${waitStatement}\n\tparentIdentity, identityErr := capturePlanBrokerCPUProcessIdentity(cmd.Process.Pid)`);
  rejectParentGuardMutant(waitBeforeIdentity, 'wait-before-original-pidfd-and-identity-validation');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, '\t\tcase <-time.After(5 * time.Second):\n\t\t\tcloseErr = errors.Join(closeErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeUnboundParentPIDFD()))', '\t\tdefault:\n\t\t\tcloseErr = errors.Join(closeErr, planBrokerCPUCleanupFailure(planBrokerCPUReasonClose, closeUnboundParentPIDFD()))'), 'unbound-wait-timeout-omitted');
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, '\t\tstartParentWait()\n\t\tselect {', '\t\twaitErr := cmd.Wait()\n\t\t_ = waitErr\n\t\tselect {'), 'unbound-wait-direct-blocking-call');
  const validateWorkerArtifactCallSites = (source) => {
    const lifecycleStart = source.indexOf('\nfunc TestCheckpointPlanRelaunchCPULifecycleSequence(t *testing.T) {');
    const crashCallStart = source.indexOf(`\nfunc ${crashTestName}(t *testing.T) {`);
    const lifecycleEnd = source.indexOf(`\nfunc ${crashTestName}(t *testing.T) {`, lifecycleStart);
    const crashCallEnd = source.indexOf('\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {', crashCallStart);
    if (lifecycleStart < 0 || lifecycleEnd <= lifecycleStart || crashCallStart < 0 || crashCallEnd <= crashCallStart) throw new Error('worker artifact call-site regions are missing or ambiguous');
    const lifecycle = source.slice(lifecycleStart, lifecycleEnd);
    const crash = source.slice(crashCallStart, crashCallEnd);
    for (const [label, region] of [['lifecycle', lifecycle], ['crash', crash]]) {
      if ((region.match(/workerSHA, err := installPlanBrokerCPUWorker\(paths\)/g) ?? []).length !== 1 || (region.match(/workerExecutable := filepath\.Join\(root, "worker"\)/g) ?? []).length !== 1 || (region.match(/writePlanBrokerCPUPlans\(paths, workerSHA\)/g) ?? []).length !== 1 || !region.includes('startPlanBrokerCPUTransient(paths, workerSHA)')) throw new Error(`${label} fixture does not keep the worker digest for plan/transient validation`);
      if (!region.includes('startPlanBrokerCPUBroker(workerExecutable, paths') || !region.includes('makePlanBrokerCPUUnrelatedChild(&unrelated, workerExecutable') || (label === 'crash' && !region.includes('runPlanBrokerCPUParentDeathOracle(workerExecutable, paths'))) throw new Error(`${label} fixture does not use the exact absolute worker executable for process launches`);
      if (region.includes('startPlanBrokerCPUBroker(workerSHA,') || region.includes('makePlanBrokerCPUUnrelatedChild(&unrelated, workerSHA,') || region.includes('runPlanBrokerCPUParentDeathOracle(workerSHA,')) throw new Error(`${label} fixture confused worker SHA with executable path`);
    }
    return true;
  };
  validateWorkerArtifactCallSites(cpuFixture);
  rejectParentGuardMutant(replaceExactlyOnce(cpuFixture, 'runPlanBrokerCPUParentDeathOracle(workerExecutable, paths', 'runPlanBrokerCPUParentDeathOracle(workerSHA, paths'), 'worker-digest-used-as-parent-executable');
  const brokerRoleStart = cpuFixture.indexOf('\nfunc TestCheckpointPlanRelaunchCPUWorker(t *testing.T) {');
  const brokerRoleEnd = cpuFixture.indexOf('\nfunc infoSysDevice', brokerRoleStart);
  if (brokerRoleStart < 0 || brokerRoleEnd <= brokerRoleStart) throw new Error('fixed broker child role source boundaries are missing');
  const brokerRole = cpuFixture.slice(brokerRoleStart, brokerRoleEnd);
  if (!brokerRole.includes('if role == "parent-helper"') || !brokerRole.includes('runPlanBrokerCPUParentDeathHelper(t)') || !brokerRole.includes('boundary == "start_requested_durable"') || !brokerRole.includes('os.Exit(planBrokerCPUCrashExit)') || !brokerRole.includes('crashAt != "start_requested_durable"')) throw new Error('tagged parent helper or broker child crash hook is missing/outside its fixed boundary');
  if (!/planBrokerCPUCrashAtEnv\s*=\s*"VRAM_PLAN_BROKER_CPU_CRASH_AT"/.test(cpuFixture) || !cpuFixture.includes('expectedCrashExit')) throw new Error('crash injection must be fixed-selector and verify exact held-child exit status');
  const custodyStart = cpuFixture.indexOf('\nfunc capturePlanBrokerCPULaunch(');
  const custodyEnd = cpuFixture.indexOf('\nfunc planBrokerCPULaunchStillCurrent(', custodyStart);
  const recheckEnd = cpuFixture.indexOf('\n// TestCheckpointPlanRelaunchCPULifecycleSequence', custodyEnd);
  if (custodyStart < 0 || custodyEnd <= custodyStart || recheckEnd <= custodyEnd) throw new Error('exact worker cleanup custody declarations are missing or unbounded');
  const launchCustody = cpuFixture.slice(custodyStart, recheckEnd);
  for (const required of ['StartTicks', 'ControlGroup', 'ExecutableDevice', 'ExecutableInode', 'ModelDevice', 'ModelInode', 'PlanSHA256', 'observePlanBrokerCPUWorker', 'checkpointProcessStart']) {
    if (!launchCustody.includes(required)) throw new Error(`exact worker cleanup custody is missing a required pin: ${required}`);
  }
  if (!launchCustody.includes('current.StartTicks != held.StartTicks') || !launchCustody.includes('current.ModelInode != held.ModelInode') || !launchCustody.includes('current.ExecutableInode != held.ExecutableInode')) throw new Error('exact worker stop does not recheck process and source pins immediately beforehand');
  const durableHook = broker.indexOf('if checkpointPlanBrokerFixtureFault(paths, "start_requested_durable") {');
  const durableSave = broker.lastIndexOf('saveCheckpointPlanBrokerJournal(paths.Journal, paths, &journal)', durableHook);
  const firstStart = broker.indexOf('checkpointFixedSystemctl, "start"', durableHook);
  if (durableHook < 0 || durableSave < 0 || firstStart <= durableHook || durableHook <= durableSave) throw new Error('crash selector no longer brackets the durable journal write before systemd start');
  if (!cpuFixture.includes('"-test.v", "-test.run=^TestCheckpointPlanRelaunchCPUNodeClient$"') || !cpuFixture.includes('stopPlanBrokerCPUUnrelatedChild') || !cpuFixture.includes('status.Signal() != syscall.SIGKILL')) throw new Error('CPU helper must capture its exact inventory and prove bounded child reaping');
  const withPrivateBinary = uniqueSourceRegion(verifier, 'function withPrivateBinary(mode) {', 'const recoveryPolicyTests =');
  const reconcileAt = withPrivateBinary.indexOf("} else if (mode === '--mode=reconcile') {");
  const cpuSequenceAt = withPrivateBinary.indexOf("const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence'", reconcileAt);
  const cpuSequenceEnd = withPrivateBinary.indexOf("console.log('checkpoint plan relaunch CPU sequence", cpuSequenceAt);
  if (reconcileAt < 0 || cpuSequenceAt < 0 || cpuSequenceEnd <= cpuSequenceAt || !withPrivateBinary.slice(reconcileAt, cpuSequenceAt).includes(`'${crashTestName}'`) || !withPrivateBinary.slice(cpuSequenceAt, cpuSequenceEnd).includes(`'${crashTestName}'`) || !withPrivateBinary.slice(reconcileAt, cpuSequenceAt).includes('TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect') || !withPrivateBinary.slice(cpuSequenceAt, cpuSequenceEnd).includes('TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect')) throw new Error('tagged start-request and parent-death oracles are not in both exact CPU/reconcile selectors');
  if (!withPrivateBinary.slice(reconcileAt, cpuSequenceAt).includes('requireReviewedCurrentFreeze();') && !withPrivateBinary.includes('requireReviewedCurrentFreeze();')) throw new Error('reconcile selection has no root-reviewed exact-pin preflight');
  const mutants = uniqueSourceRegion(verifier, 'function verifyCompiledBehavioralMutants(temp) {', 'function executeInventory(');
  if (!mutants.includes("'mutant-repeat-ambiguous-start'") || !mutants.includes("'mutant-join-before-start-request'")) throw new Error('compiled behavioral mutants for both recovery predicates are not registered in the actual mutant runner');
  if (!mutants.includes("'mutant-cpu-repeat-start-requested'") || !mutants.includes(`'${crashTestName}'`) || !mutants.includes('"_published" || stage == step+"_start_requested"') || !mutants.includes("'checkpoint_plan_broker_cpu', true") || !mutants.includes('ambiguous start recovery changed unit/MainPID')) throw new Error('CPU first-start mutant is not registered with its tagged decisive unit-change oracle');
  for (const required of ["'mutant-holder-omitted-retention'", "'mutant-holder-early-release'", "'mutant-holder-eof-parent-alive'", "'negative-holder-ref-error'", "'negative-holder-watchdog-omitted'", "'mutant-holder-ref-error-ignored'", "'mutant-holder-watchdog-proof-ignored'", "__PLAN_RELAUNCH_HOLDER_RETENTION_MISSING_DEFINITION__", "__PLAN_RELAUNCH_HOLDER_EARLY_RELEASE_MISSING_DEFINITION__", "__PLAN_RELAUNCH_HOLDER_EOF_PARENT_ALIVE_CONFIRMED__", "negative_ref_error: normal holder acquisition consumed the exact injected pre-RefUnit error", "__PLAN_RELAUNCH_REF_ERROR_NOT_CONSUMED__", "negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned", "__PLAN_RELAUNCH_WATCHDOG_OMISSION_ORACLE_BYPASSED__", "planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeRefError", "planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeWatchdogOmit", "'checkpoint_plan_broker_cpu', true"]) if (!mutants.includes(required)) throw new Error(`compiled holder retention/negative controls are missing ${required}`);
  const mustReject = uniqueSourceRegion(verifier, 'function compileBehavioralMutantMustReject(', '\nfunction fixedWslTestArgv(');
  if (!mustReject.includes('additionalEdits = []') || mustReject.includes('catch (') || !mustReject.includes('return executeExpectedFailureInventory(binary, testName, expectedFailure, true)')) throw new Error('ignored-proof mutants must apply explicit case activation edits and require a successful exact named result, not classifier exceptions');
  const cpuBranch = withPrivateBinary.slice(cpuSequenceAt, cpuSequenceEnd);
  const positiveRunAt = cpuBranch.indexOf('const output = executeInventory(binary, selected, 240, true);');
  const positiveMarkerAt = cpuBranch.indexOf("output.split('__PLAN_RELAUNCH_CPU_SEQUENCE_POSITIVE__')", positiveRunAt);
  const mutantCallAt = cpuBranch.indexOf('verifyCompiledBehavioralMutants(temp);');
  if (positiveRunAt < 0 || positiveMarkerAt <= positiveRunAt || !cpuBranch.includes("output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__')") || mutantCallAt <= positiveMarkerAt) throw new Error('CPU parent-death and first-start controls must follow the exact positive fixture inventory');
  const reconcileBranch = withPrivateBinary.slice(reconcileAt, cpuSequenceAt);
  if (!reconcileBranch.includes("output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__')") || !reconcileBranch.includes('const output = executeInventory(binary, selected, 240, true);')) throw new Error('reconcile inventory must require exactly one executed parent-death positive marker');
  const reconcilePositiveCheck = reconcileBranch.indexOf("output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__')");
  const reconcileMutants = reconcileBranch.indexOf("verifyCompiledParentDeathMutants(temp, 'reconcile');");
  const reconcileTransportMutant = reconcileBranch.indexOf("verifyCompiledRequestHalfCloseMutant(temp, 'reconcile');");
  const cpuPositiveCheck = cpuBranch.indexOf("output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__')");
  const cpuMutants = cpuBranch.indexOf("verifyCompiledParentDeathMutants(temp, 'cpu-sequence');");
  const cpuTransportMutant = cpuBranch.indexOf("verifyCompiledRequestHalfCloseMutant(temp, 'cpu-sequence');");
  if (reconcilePositiveCheck < 0 || reconcileMutants <= reconcilePositiveCheck || reconcileTransportMutant <= reconcileMutants || cpuPositiveCheck < 0 || cpuMutants <= cpuPositiveCheck || cpuTransportMutant <= cpuMutants) throw new Error('compiled EOF, leaked-writer, and missing-half-close mutants must follow their known positives in both runtime modes');
  const authorityBranch = withPrivateBinary.slice(0, reconcileAt);
  if (!authorityBranch.includes("nodeTests.push('TestPlanBrokerRequestHalfCloseUnixStream', 'TestPlanBrokerRequestHalfCloseRejectsWriteFaults');")) throw new Error('authority inventory omits both exact local transport tests');
  if (!authorityBranch.includes(`'${catalogName}'`) || !authorityBranch.includes('executeInventory(nodeBinary, nodeTests, 90, true);')) throw new Error('authority inventory must retain the catalog test under its explicit existing private-fixture opt-in');
  const parentMutants = uniqueSourceRegion(verifier, 'function verifyCompiledParentDeathMutants(temp, mode) {', 'function verifyCompiledRequestHalfCloseMutant(');
  const validateCompiledParentMutantRunner = (region) => {
    for (const required of ["'mutant-parent-missing-eof-' + mode", "'mutant-parent-leaked-writer-' + mode", 'if errors.Is(err, io.EOF)', 'cmd.ExtraFiles = []*os.File{guardRead, readyWrite, guardWrite}', '__PLAN_RELAUNCH_PARENT_DEATH_SURVIVOR_ASSERTED__', '__PLAN_RELAUNCH_PARENT_DEATH_PIDFD_CLEANUP_PROVED__', '__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__']) if (!region.includes(required)) throw new Error(`compiled parent-death negative controls are incomplete: ${required}`);
    if ((region.match(/compileBehavioralMutant\(/g) ?? []).length !== 2 || !region.includes('true, cleanupEvidence')) throw new Error('parent-death negative runner must compile exactly the EOF and leaked-writer mutants with exact uncertainty evidence');
    return true;
  };
  validateCompiledParentMutantRunner(parentMutants);
  const missingWriterControl = parentMutants.replace("'mutant-parent-leaked-writer-' + mode", '');
  let missingWriterRejected = false;
  try { validateCompiledParentMutantRunner(missingWriterControl); } catch { missingWriterRejected = true; }
  if (!missingWriterRejected) throw new Error('parent-death compiled-mutant validator accepted removal of the leaked-writer scenario');
  const dispatchStart = verifier.indexOf('\nconst recoveryPolicyTests = [');
  const dispatch = dispatchStart < 0 ? '' : verifier.slice(dispatchStart);
  const sourceRoute = dispatch.indexOf("if (argv[0] === '--mode=source-only') {");
  const runtimeCall = dispatch.indexOf('withPrivateBinary(argv[0]);');
  if (sourceRoute < 0 || runtimeCall <= sourceRoute || withPrivateBinary.indexOf('mkdtempSync(') < 0 || withPrivateBinary.indexOf('requireReviewedCurrentFreeze();') > withPrivateBinary.indexOf('mkdtempSync(')) throw new Error('source-only route or enabled-mode exact-pin preflight is not ordered before private workspace/compiler/runtime creation');
  if (!dispatch.includes('parent-death EOF oracle is source-present but unexecuted')) throw new Error('source-only disclosure must state that parent-death runtime remains unexecuted');
  const selectedNames = ['TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart', crashTestName];
  return { expectedPortable, selectedNames };
}

const sourceControls = sourceOnlyControls();

function wslPath(localPath) {
  const result = run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'wslpath', '-a', localPath]).trim();
  if (!result.startsWith('/') || result.includes('\n') || result.includes('\r')) throw new Error('workspace path did not map to one canonical WSL path');
  return result;
}

function compileLinuxBinary(pkg, temp, name, tags = '', overlay = '') {
  const binary = path.join(temp, name);
  const env = { ...process.env, CGO_ENABLED: '0', GOOS: 'linux', GOARCH: 'amd64', GOENV: 'off', GOFLAGS: '', GOTOOLCHAIN: 'local' };
  run('go', ['test', '-c', ...(tags ? ['-tags', tags] : []), ...(overlay ? ['-overlay', overlay] : []), '-o', binary, pkg], { env });
  return binary;
}

function compileBehavioralMutant(temp, name, sourceRelative, needle, replacement, testName, expectedFailure, tags = '', optIn = false, cleanupEvidence = []) {
  const originalPath = path.resolve(root, sourceRelative);
  const original = readFileSync(originalPath, 'utf8');
  const edits = Array.isArray(needle) ? needle : [[needle, replacement]];
  let mutated = original;
  for (const [before, after] of edits) {
    if (mutated.split(before).length !== 2) throw new Error(`compiled mutant source anchor is not unique: ${sourceRelative}`);
    mutated = mutated.replace(before, after);
  }
  const mutatedPath = path.join(temp, `${name}.go`);
  const overlayPath = path.join(temp, `${name}.overlay.json`);
  writeFileSync(mutatedPath, mutated, { flag: 'wx', mode: 0o600 });
  writeFileSync(overlayPath, JSON.stringify({ Replace: { [originalPath]: mutatedPath } }), { flag: 'wx', mode: 0o600 });
  const binary = compileLinuxBinary('./internal/nodeagent', temp, `${name}.test`, tags, overlayPath);
  executeExpectedFailureInventory(binary, testName, expectedFailure, optIn, cleanupEvidence);
}

function compileBehavioralMutantMustReject(temp, name, sourceRelative, needle, replacement, testName, expectedFailure, additionalEdits = []) {
  const originalPath = path.resolve(root, sourceRelative);
  const original = readFileSync(originalPath, 'utf8');
  if (original.split(needle).length !== 2) throw new Error(`compiled negative-oracle mutant anchor is not exact-once: ${sourceRelative}`);
  let mutated = original.replace(needle, replacement);
  for (const [extraNeedle, extraReplacement] of additionalEdits) {
    if (mutated.split(extraNeedle).length !== 2) throw new Error(`compiled negative-oracle activation anchor is not exact-once: ${sourceRelative}`);
    mutated = mutated.replace(extraNeedle, extraReplacement);
  }
  const mutatedPath = path.join(temp, `${name}.go`);
  const overlayPath = path.join(temp, `${name}.overlay.json`);
  writeFileSync(mutatedPath, mutated, { flag: 'wx', mode: 0o600 });
  writeFileSync(overlayPath, JSON.stringify({ Replace: { [originalPath]: mutatedPath } }), { flag: 'wx', mode: 0o600 });
  const binary = compileLinuxBinary('./internal/nodeagent', temp, `${name}.test`, 'checkpoint_plan_broker_cpu', overlayPath);
  return executeExpectedFailureInventory(binary, testName, expectedFailure, true);
}

function fixedWslTestArgv(optIn, positional) {
  if (optIn !== true && optIn !== false) throw new Error('fixed WSL opt-in must be boolean');
  if (!Array.isArray(positional) || positional.some((value) => typeof value !== 'string')) throw new Error('fixed WSL arguments must be strings');
  return ['-d', 'Ubuntu', ...(optIn === true ? ['--user', 'root'] : []), '--exec', 'bash', '--noprofile', '--norc', '-s', '--', ...positional];
}

function validateFixedRootTransportSource(source) {
  const helper = uniqueSourceRegion(source, 'function fixedWslTestArgv(', '\nfunction validateFixedRootTransportSource(');
  const expectedHelper = `function fixedWslTestArgv(optIn, positional) {
  if (optIn !== true && optIn !== false) throw new Error('fixed WSL opt-in must be boolean');
  if (!Array.isArray(positional) || positional.some((value) => typeof value !== 'string')) throw new Error('fixed WSL arguments must be strings');
  return ['-d', 'Ubuntu', ...(optIn === true ? ['--user', 'root'] : []), '--exec', 'bash', '--noprofile', '--norc', '-s', '--', ...positional];
}`;
  const normalizedExpectedHelper = `${expectedHelper}\n`;
  if (helper !== normalizedExpectedHelper) throw new Error('fixed WSL argv helper must choose only literal Ubuntu root for boolean opt-in');

  const expectedFailure = uniqueSourceRegion(source, 'function executeExpectedFailureInventory(', '\nfunction verifyCompiledBehavioralMutants(');
  const inventory = uniqueSourceRegion(source, 'function executeInventory(', '\nfunction withPrivateBinary(');
  const classifier = uniqueSourceRegion(source, 'function classifyExpectedFailureResult(', '\nfunction selfTestExpectedFailureClassifier(');
  const mustReject = uniqueSourceRegion(source, 'function compileBehavioralMutantMustReject(', '\nfunction fixedWslTestArgv(');
  const expectedFailureSpawn = "spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, optIn ? 'yes' : 'no']), {";
  const inventorySpawn = "spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, `${timeout}s`, `${timeout - 10}s`, optIn ? 'yes' : 'no']), {";
  if ((expectedFailure.match(/spawnSync\('wsl\.exe'/g) ?? []).length !== 1 || !expectedFailure.includes(expectedFailureSpawn)) throw new Error('expected-failure opt-in route must consume the fixed argv builder exactly once');
  if (!expectedFailure.includes('classifyExpectedFailureResult(result, testName, expectedFailure)')) throw new Error('actual expected-failure runner must consume the strict pure child-result classifier');
  for (const required of ['result.error', 'result.status === null', 'result.status === undefined', 'result.status !== 1', 'output.split(expectedPredicate).length !== 2', 'JSON.stringify(events) !== JSON.stringify([']) if (!classifier.includes(required)) throw new Error(`expected-failure classifier does not require a named confirmed child result: ${required}`);
  if (mustReject.includes('catch (') || !mustReject.includes('return executeExpectedFailureInventory(binary, testName, expectedFailure, true)')) throw new Error('ignored-proof mutants must accept only a successful exact child-classifier result; exceptions are uncertainty');
  if ((inventory.match(/spawnSync\('wsl\.exe'/g) ?? []).length !== 1 || !inventory.includes(inventorySpawn)) throw new Error('inventory opt-in route must consume the fixed argv builder exactly once');
  const expectedFailureOptIn = 'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=10s 180s "$binary" -test.v -test.count=1 -test.timeout=170s -test.run="$selection"; fi';
  const inventoryOptIn = 'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=10s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"; fi';
  const expectedFailureDefault = 'exec timeout --signal=TERM --kill-after=5s 60s "$binary" -test.v -test.count=1 -test.timeout=50s -test.run="$selection"';
  const inventoryDefault = 'exec timeout --signal=TERM --kill-after=10s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"';
  if (!expectedFailure.includes(expectedFailureOptIn) || expectedFailure.includes('sudo')) throw new Error('expected-failure opt-in shell lost acknowledgement/bounds or reintroduced sudo');
  if (!inventory.includes(inventoryOptIn) || inventory.includes('sudo')) throw new Error('inventory opt-in shell lost acknowledgement/bounds or reintroduced sudo');
  if (!expectedFailure.includes(expectedFailureDefault) || !inventory.includes(inventoryDefault)) throw new Error('default-user execution bounds or test arguments changed');
  const wslPathSource = uniqueSourceRegion(source, 'function wslPath(localPath) {', '\nfunction compileLinuxBinary(');
  if (wslPathSource !== `function wslPath(localPath) {
  const result = run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'wslpath', '-a', localPath]).trim();
  if (!result.startsWith('/') || result.includes('\\n') || result.includes('\\r')) throw new Error('workspace path did not map to one canonical WSL path');
  return result;
}` + '\n') throw new Error('read-only WSL path mapping must remain default-user');
  const compileSource = uniqueSourceRegion(source, 'function compileLinuxBinary(', '\nfunction compileBehavioralMutant(');
  if (!compileSource.includes("run('go', ['test', '-c', ...(tags ? ['-tags', tags] : []), ...(overlay ? ['-overlay', overlay] : []), '-o', binary, pkg], { env })")) throw new Error('fixed host compiler route changed');
  return true;
}

function selfTestFixedRootTransportSource(source) {
  validateFixedRootTransportSource(source);
  const positional = ['/repo with spaces', '/tmp/test binary', '^TestFixed$', '240s', '230s', 'yes'];
  const defaultArgv = fixedWslTestArgv(false, positional);
  const rootArgv = fixedWslTestArgv(true, positional);
  const expectedBase = ['-d', 'Ubuntu'];
  const suffix = ['--exec', 'bash', '--noprofile', '--norc', '-s', '--', ...positional];
  if (JSON.stringify(defaultArgv) !== JSON.stringify([...expectedBase, ...suffix])) throw new Error('default-user full WSL argv differs from fixed expected argv');
  if (JSON.stringify(rootArgv) !== JSON.stringify([...expectedBase, '--user', 'root', ...suffix])) throw new Error('opt-in root full WSL argv differs from fixed expected argv');
  for (const invalid of ['yes', 1, null, undefined]) {
    let rejected = false;
    try { fixedWslTestArgv(invalid, positional); } catch { rejected = true; }
    if (!rejected) throw new Error('fixed WSL argv builder accepted a non-boolean opt-in');
  }
  const replaceOnce = (text, before, after) => {
    if (text.split(before).length !== 2) throw new Error('root transport source mutant anchor is not exact-once');
    return text.replace(before, after);
  };
  const mutateRegion = (start, end, before, after) => {
    const startNeedle = `\n${start}`, endNeedle = `\n${end}`;
    const startAt = source.indexOf(startNeedle), endAt = source.indexOf(endNeedle, startAt + startNeedle.length);
    if (startAt < 0 || endAt <= startAt || source.indexOf(startNeedle, startAt + startNeedle.length) >= 0) throw new Error('root transport mutant region is missing or ambiguous');
    const region = source.slice(startAt + 1, endAt + 1);
    return source.slice(0, startAt + 1) + replaceOnce(region, before, after) + source.slice(endAt + 1);
  };
  const reject = (mutant, label, expectedReason) => {
    let rejected = false;
    let reason = '';
    try { validateFixedRootTransportSource(mutant); } catch (error) { rejected = true; reason = String(error?.message ?? error); }
    if (!rejected || !reason.includes(expectedReason)) throw new Error(`fixed-root source control did not target-reject ${label}: ${reason || 'accepted'}`);
  };
  const helperGuard = 'fixed WSL argv helper must choose only literal Ubuntu root for boolean opt-in';
  const expectedFailureGuard = 'expected-failure classifier does not require a named confirmed child result';
  reject(mutateRegion('function executeExpectedFailureInventory(', '\nfunction verifyCompiledBehavioralMutants(', 'classifyExpectedFailureResult(result, testName, expectedFailure)', 'return { status: 1 }'), 'expected-failure runner bypasses exact status/inventory/predicate classifier', 'actual expected-failure runner must consume');
  reject(mutateRegion('function classifyExpectedFailureResult(', '\nfunction selfTestExpectedFailureClassifier(', 'if (!result || result.error || result.status === null || result.status === undefined) {', 'if (!result || result.error) {'), 'timeout remains admissible as expected failure', expectedFailureGuard);
  reject(mutateRegion('function classifyExpectedFailureResult(', '\nfunction selfTestExpectedFailureClassifier(', 'if (result.status !== 1)', 'if (result.status < 0)'), 'unrelated exit status remains admissible', expectedFailureGuard);
  reject(mutateRegion('function classifyExpectedFailureResult(', '\nfunction selfTestExpectedFailureClassifier(', 'output.split(expectedPredicate).length !== 2', 'output.includes(expectedPredicate)'), 'shared or repeated marker remains admissible', expectedFailureGuard);
  reject(mutateRegion('function fixedWslTestArgv(', '\nfunction validateFixedRootTransportSource(', "...(optIn === true ? ['--user', 'root'] : [])", '...[]'), 'missing opt-in root selector', helperGuard);
  reject(mutateRegion('function fixedWslTestArgv(', '\nfunction validateFixedRootTransportSource(', "...(optIn === true ? ['--user', 'root'] : [])", "...['--user', 'root']"), 'unconditional root selector', helperGuard);
  reject(mutateRegion('function fixedWslTestArgv(', '\nfunction validateFixedRootTransportSource(', "'Ubuntu', ...(optIn === true ? ['--user', 'root'] : [])", "optIn ? 'Ubuntu' : 'other', ...(optIn === true ? ['--user', 'root'] : [])"), 'dynamic distribution', helperGuard);
  reject(mutateRegion('function fixedWslTestArgv(', '\nfunction validateFixedRootTransportSource(', "['--user', 'root']", "['--user', positional[0]]"), 'dynamic user selector', helperGuard);
  reject(mutateRegion('function executeExpectedFailureInventory(', '\nfunction verifyCompiledBehavioralMutants(', "spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, optIn ? 'yes' : 'no']), {", "spawnSync('wsl.exe', ['-d', 'Ubuntu', '--exec', 'bash', '--noprofile', '--norc', '-s', '--', linuxRepo, linuxBinary, selection, optIn ? 'yes' : 'no'], {"), 'expected-failure spawn bypass', 'expected-failure opt-in route must consume');
  reject(mutateRegion('function executeInventory(', '\nfunction withPrivateBinary(', "spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, `${timeout}s`, `${timeout - 10}s`, optIn ? 'yes' : 'no']), {", "spawnSync('wsl.exe', ['-d', 'Ubuntu', '--exec', 'bash', '--noprofile', '--norc', '-s', '--', linuxRepo, linuxBinary, selection, `${timeout}s`, `${timeout - 10}s`, optIn ? 'yes' : 'no'], {"), 'inventory spawn bypass', 'inventory opt-in route must consume');
  reject(mutateRegion('function executeExpectedFailureInventory(', '\nfunction verifyCompiledBehavioralMutants(', 'then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS', 'then exec sudo -n -- env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS'), 'sudo reintroduction', 'expected-failure opt-in shell lost acknowledgement/bounds');
  reject(mutateRegion('function executeInventory(', '\nfunction withPrivateBinary(', 'VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS', 'VRAM_PLAN_BROKER_CPU_OPT_IN=REMOVED'), 'missing opt-in acknowledgement', 'inventory opt-in shell lost acknowledgement/bounds');
  reject(mutateRegion('function executeExpectedFailureInventory(', '\nfunction verifyCompiledBehavioralMutants(', 'timeout --signal=TERM --kill-after=10s 180s', 'timeout --signal=TERM --kill-after=9s 180s'), 'expected-failure bound change', 'expected-failure opt-in shell lost acknowledgement/bounds');
  reject(mutateRegion('function executeInventory(', '\nfunction withPrivateBinary(', 'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=10s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"; fi', 'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=9s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"; fi'), 'inventory bound change', 'inventory opt-in shell lost acknowledgement/bounds');
  return true;
}

function classifyExpectedFailureResult(result, testName, expectedPredicate) {
  if (!result || result.error || result.status === null || result.status === undefined) {
    throw new Error('compiled expected-failure child has no confirmed bounded exit status');
  }
  if (result.status !== 1) throw new Error('compiled expected-failure child did not exit with the exact Go test failure status');
  if (typeof testName !== 'string' || !testName || typeof expectedPredicate !== 'string' || !expectedPredicate || /[\r\n]/.test(expectedPredicate)) {
    throw new Error('compiled expected-failure predicate identity is not a fixed single-line value');
  }
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const events = [];
  for (const line of output.split(/\r?\n/)) {
    const runMatch = line.match(/^=== RUN\s+(\S+)\s*$/);
    const failMatch = line.match(/^--- FAIL:\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
    if (/^=== RUN(?:\s|$)/.test(line) && !runMatch) throw new Error('compiled expected-failure RUN event is malformed');
    if (/^--- (PASS|SKIP|FAIL):/.test(line) && !failMatch) throw new Error('compiled expected-failure result event is not one exact FAIL');
    if (runMatch) events.push(`RUN:${runMatch[1]}`);
    if (failMatch) events.push(`FAIL:${failMatch[1]}`);
  }
  if (JSON.stringify(events) !== JSON.stringify([`RUN:${testName}`, `FAIL:${testName}`])) {
    throw new Error('compiled expected-failure child did not produce exactly one RUN and one matching FAIL');
  }
  if (output.split(expectedPredicate).length !== 2) throw new Error('compiled expected-failure child did not emit exactly one intended named predicate');
  return { status: 1, testName, events, expectedPredicate };
}

function selfTestExpectedFailureClassifier() {
  const testName = 'TestOwnedNegative';
  const marker = '__OWNED_WRONG_BEHAVIOR__';
  const positive = { error: null, status: 1, stdout: `=== RUN   ${testName}\n${marker}\n--- FAIL: ${testName} (0.01s)\n`, stderr: '' };
  const proof = classifyExpectedFailureResult(positive, testName, marker);
  if (proof.status !== 1 || proof.events.length !== 2 || proof.expectedPredicate !== marker) throw new Error('known positive named failure proof did not retain its exact child outcome');
  const reject = (mutant, label) => {
    let failed = false;
    try { classifyExpectedFailureResult(mutant, testName, marker); } catch { failed = true; }
    if (!failed) throw new Error(`expected-failure classifier accepted ${label}`);
  };
  reject({ error: new Error('timeout'), status: null, stdout: positive.stdout, stderr: '' }, 'timeout without child status');
  reject({ error: null, status: null, stdout: positive.stdout, stderr: '' }, 'null child status');
  reject({ error: null, status: 0, stdout: positive.stdout, stderr: '' }, 'status-zero child');
  reject({ error: null, status: 2, stdout: positive.stdout, stderr: '' }, 'unrelated child status');
  reject({ error: null, status: 1, stdout: `=== RUN ${testName}\n--- FAIL: OtherTest (0.01s)\n${marker}\n`, stderr: '' }, 'wrong test inventory');
  reject({ error: null, status: 1, stdout: `=== RUN ${testName}\n${marker}\n=== RUN ${testName}\n--- FAIL: ${testName} (0.01s)\n`, stderr: '' }, 'duplicate RUN inventory');
  reject({ error: null, status: 1, stdout: `=== RUN ${testName}\n--- FAIL: ${testName} (0.01s)\n`, stderr: '' }, 'absent predicate');
  reject({ error: null, status: 1, stdout: `=== RUN ${testName}\n${marker}\n${marker}\n--- FAIL: ${testName} (0.01s)\n`, stderr: '' }, 'repeated predicate');
  reject({ error: null, status: 1, stdout: positive.stdout.replace(marker, '__UNRELATED_FAILURE__'), stderr: '' }, 'unrelated status-one predicate');
}

function executeExpectedFailureInventory(binary, testName, expectedFailure, optIn = false, cleanupEvidence = []) {
  const preserveBefore = preservePrivateWorkspace;
  if (optIn) preservePrivateWorkspace = true;
  const linuxRepo = wslPath(root), linuxBinary = wslPath(binary);
  const selection = `^${testName}$`;
  const shell = [
    'set -eu',
    'repo=$1; binary=$2; selection=$3; opt_in=$4',
    'cd -- "$repo"',
    'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=10s 180s "$binary" -test.v -test.count=1 -test.timeout=170s -test.run="$selection"; fi',
    'exec timeout --signal=TERM --kill-after=5s 60s "$binary" -test.v -test.count=1 -test.timeout=50s -test.run="$selection"',
  ].join('\n');
  const result = spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, optIn ? 'yes' : 'no']), {
    cwd: root, encoding: 'utf8', input: shell, timeout: optIn ? 210_000 : 90_000, maxBuffer: 2 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.error || result.status === null) throw new Error(`compiled expected-failure inventory has no confirmed bounded child exit: ${result.error?.code ?? 'missing status'}`);
  if (result.status !== 1) throw new Error(`compiled expected-failure inventory exited ${result.status}; only the fixed Go test failure status is admissible`);
  if (optIn && output.includes('bounded fixture cleanup failed')) {
    if (cleanupEvidence.length === 0) {
      preservePrivateWorkspace = true;
      throw new Error('compiled CPU mutant cleanup is uncertain; preserving its private workspace');
    }
    const cleanupLines = output.split(/\r?\n/).filter((line) => line.includes('bounded fixture cleanup failed'));
    const cleanupLine = cleanupLines[0] ?? '';
    const cleanupLineAt = output.indexOf(cleanupLine);
    const expectedFailureAt = output.indexOf(`--- FAIL: ${testName}`);
    const cleanupTail = cleanupLineAt < 0 || expectedFailureAt < cleanupLineAt ? 'ambiguous' : output.slice(cleanupLineAt + cleanupLine.length, expectedFailureAt).trim();
    if (cleanupLines.length !== 1 || !cleanupLine.endsWith(': private fixture identity is uncertain; preserving it') || cleanupTail !== '') {
      preservePrivateWorkspace = true;
      throw new Error('parent-death negative did not preserve exactly its expected private-root uncertainty');
    }
    for (const evidence of cleanupEvidence) {
      if (output.split(evidence).length !== 2) {
        preservePrivateWorkspace = true;
        throw new Error('parent-death negative lacks one exact survivor, pidfd cleanup, or root-preservation proof');
      }
    }
  } else if (optIn && cleanupEvidence.length !== 0) {
    preservePrivateWorkspace = true;
    throw new Error('parent-death negative did not report expected preserved-root cleanup uncertainty');
  }
  const proof = classifyExpectedFailureResult(result, testName, expectedFailure);
  if (optIn) preservePrivateWorkspace = preserveBefore;
  return proof;
}

function verifyCompiledBehavioralMutants(temp) {
  compileBehavioralMutant(
    temp, 'mutant-pending-unit-substring', 'internal/nodeagent/checkpoint_lifecycle_broker_linux.go',
    'if fields[1] == unit {', 'if strings.Contains(fields[1], unit) {',
    'TestPlanBrokerJobParserUsesExactUnitIdentity', 'substring-matching unrelated unit was treated as pending',
  );
  compileBehavioralMutant(
    temp, 'mutant-late-acceptance', 'internal/nodeagent/checkpoint_plan_rotation.go',
    'acceptedAt.Before(original.IssuedAt) || acceptedAt.After(original.ExpiresAt) || signedAt.Before(acceptedAt)',
    'acceptedAt.Before(original.IssuedAt) || signedAt.Before(acceptedAt)',
    'TestPlanRelaunchReceiptReconcilesOnlyPreviouslyAcceptedExpiredIntent', 'root receipt accepted an intent first accepted after its signed expiry',
  );
  compileBehavioralMutant(
    temp, 'mutant-repeat-ambiguous-start', 'internal/nodeagent/checkpoint_plan_rotation.go',
    'return stage == step+"_published"', 'return stage == step+"_published" || stage == step+"_start_requested"',
    'TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart', 'first-start authority for urgent_load/urgent_load_start_requested',
  );
  compileBehavioralMutant(
    temp, 'mutant-join-before-start-request', 'internal/nodeagent/checkpoint_plan_rotation.go',
    'return stage == step+"_start_requested" || stage == step+"_start_accepted"',
    'return stage == step+"_start_requested" || stage == step+"_start_accepted" || stage == step+"_published"',
    'TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart', 'live-process join authority for urgent_load/urgent_load_published',
  );
  compileBehavioralMutant(
    temp, 'mutant-cpu-repeat-start-requested', 'internal/nodeagent/checkpoint_plan_rotation.go',
    'return stage == step+"_published"', 'return stage == step+"_published" || stage == step+"_start_requested"',
    'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect', 'ambiguous start recovery changed unit/MainPID', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutant(
    temp, 'mutant-holder-omitted-retention', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    [
      ['runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)', 'nil'],
      ['holder, err = startPlanBrokerCPUUnitHolder(paths, rootInfo, victimLaunch, 27)', 'holder, err = nil, nil'],
    ],
    '',
    'TestCheckpointPlanRelaunchCPULifecycleSequence', '__PLAN_RELAUNCH_HOLDER_RETENTION_MISSING_DEFINITION__', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutant(
    temp, 'mutant-holder-early-release', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    [
      ['runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)', 'nil'],
      ['if err := holder.health(); err != nil {\n\t\tt.Fatal("holder same-connection health failed before first exact unit stop")\n\t}', 'if err := holder.health(); err != nil {\n\t\tt.Fatal("holder same-connection health failed before first exact unit stop")\n\t}\n\tif err := holder.release(); err != nil { t.Fatalf("mutant early release setup: %v", err) }'],
    ],
    '',
    'TestCheckpointPlanRelaunchCPULifecycleSequence', '__PLAN_RELAUNCH_HOLDER_EARLY_RELEASE_MISSING_DEFINITION__', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutant(
    temp, 'mutant-holder-eof-parent-alive', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    [
      ['runPlanBrokerCPUHolderControlMatrix(paths, root, rootInfo, victimLaunch, initialWorkerLaunchRequestedAt)', 'nil'],
      ['if err := planBrokerCPUHolderEOFParentAliveOutcome(holder, paths, victimLaunch, rootInfo); err != nil {', 'if closeErr := holder.guard.Close(); closeErr != nil { t.Fatalf("mutant EOF control close failed: %v", closeErr) }; holder.guard = nil\n\tif err := planBrokerCPUHolderEOFParentAliveOutcome(holder, paths, victimLaunch, rootInfo); err != nil {'],
    ],
    '',
    'TestCheckpointPlanRelaunchCPULifecycleSequence', '__PLAN_RELAUNCH_HOLDER_EOF_PARENT_ALIVE_CONFIRMED__', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutant(
    temp, 'negative-holder-ref-error', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = ""',
    'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeRefError',
    'TestCheckpointPlanRelaunchCPULifecycleSequence',
    'negative_ref_error: normal holder acquisition consumed the exact injected pre-RefUnit error', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutant(
    temp, 'negative-holder-watchdog-omitted', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = ""',
    'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeWatchdogOmit',
    'TestCheckpointPlanRelaunchCPULifecycleSequence',
    'negative_watchdog_omitted: helper survived parent death beyond five seconds and was pidfd-cleaned', 'checkpoint_plan_broker_cpu', true,
  );
  compileBehavioralMutantMustReject(
    temp, 'mutant-holder-ref-error-ignored', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'if isPlanBrokerCPUInjectedRefError(err) {', 'if false {',
    'TestCheckpointPlanRelaunchCPULifecycleSequence',
    '__PLAN_RELAUNCH_REF_ERROR_NOT_CONSUMED__',
    [['planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = ""', 'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeRefError']],
  );
  compileBehavioralMutantMustReject(
    temp, 'mutant-holder-watchdog-proof-ignored', 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'if planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {\n\t\tcontrolDeadline :=', 'if false && planBrokerCPUHolderNegativeControl == planBrokerCPUControlNegativeWatchdogOmit {\n\t\tcontrolDeadline :=',
    'TestCheckpointPlanRelaunchCPULifecycleSequence',
    '__PLAN_RELAUNCH_WATCHDOG_OMISSION_ORACLE_BYPASSED__',
    [['planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = ""', 'planBrokerCPUHolderNegativeControl planBrokerCPUHolderControl = planBrokerCPUControlNegativeWatchdogOmit']],
  );
  console.log('checkpoint plan relaunch compiled behavioral mutants rejected');
}

function verifyCompiledParentDeathMutants(temp, mode) {
  if (mode !== 'reconcile' && mode !== 'cpu-sequence') throw new Error('parent-death mutants require one exact CPU mode');
  const testName = 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect';
  const cleanupEvidence = [
    '__PLAN_RELAUNCH_PARENT_DEATH_SURVIVOR_ASSERTED__',
    '__PLAN_RELAUNCH_PARENT_DEATH_PIDFD_CLEANUP_PROVED__',
    '__PLAN_RELAUNCH_PARENT_DEATH_ROOT_PRESERVED__',
  ];
  compileBehavioralMutant(
    temp, 'mutant-parent-missing-eof-' + mode, 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'if n != 0 || !errors.Is(err, io.EOF) {\n\t\t\tcancel()\n\t\t\treturn\n\t\t}\n\t\tcancel()',
    'if errors.Is(err, io.EOF) {\n\t\t\treturn\n\t\t}\n\t\tif n != 0 { cancel(); return }; cancel()',
    testName, cleanupEvidence[0], 'checkpoint_plan_broker_cpu', true, cleanupEvidence,
  );
  compileBehavioralMutant(
    temp, 'mutant-parent-leaked-writer-' + mode, 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go',
    'cmd.ExtraFiles = []*os.File{guardRead, readyWrite}',
    'cmd.ExtraFiles = []*os.File{guardRead, readyWrite, guardWrite}',
    testName, cleanupEvidence[0], 'checkpoint_plan_broker_cpu', true, cleanupEvidence,
  );
}

function verifyCompiledRequestHalfCloseMutant(temp, mode) {
  if (mode !== 'reconcile' && mode !== 'cpu-sequence') throw new Error('request half-close mutant requires one exact CPU mode');
  compileBehavioralMutant(
    temp, 'mutant-request-missing-closewrite-' + mode, 'internal/nodeagent/checkpoint_lifecycle_broker_linux.go',
    '\tif err := conn.CloseWrite(); err != nil {\n\t\treturn fmt.Errorf("fixed plan broker request half-close failed: %w", err)\n\t}',
    '\t// mutant omitted the request half-close',
    'TestPlanBrokerRequestHalfCloseUnixStream', 'ordinary request did not receive response after half-close',
  );
}

function verifyCompiledHolderDiagnosticMutants(temp, mode) {
  if (mode !== 'reconcile' && mode !== 'cpu-sequence') throw new Error('holder diagnostic mutants require one original CPU mode');
  const source = 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go';
  const testName = 'TestPlanBrokerCPUFailureMarkerControlsPure';
  const expectedFailure = '__PLAN_RELAUNCH_PURE_DIAGNOSTIC_CONTROL_FAILURE__: actual matrix wrapper did not value-copy the selected native diagnostic while preserving primary-first causes';
  const diagnosticBlock = '\tdiagnostic := *inner.helperReadDiagnostic\n\tplanBrokerCPUFailureAttachHolderReadDiagnostic(wrapped, diagnostic)';
  compileBehavioralMutant(
    temp, `holder-diagnostic-omission-${mode}`, source, [[diagnosticBlock, '\t// omitted diagnostic attachment by compiled control']],
    '', testName, expectedFailure,
    'checkpoint_plan_broker_cpu', false,
  );
  compileBehavioralMutant(
    temp, `holder-diagnostic-alias-${mode}`, source, [[diagnosticBlock, '\twrappedFailure.helperReadDiagnostic = inner.helperReadDiagnostic']],
    '', testName, expectedFailure,
    'checkpoint_plan_broker_cpu', false,
  );
}

function verifyCompiledDescriptorGuardMutants(temp, mode) {
  if (mode !== 'reconcile' && mode !== 'cpu-sequence') throw new Error('descriptor guard mutants require one exact CPU mode');
  const source = 'internal/nodeagent/checkpoint_plan_rotation_linux_test.go';
  compileBehavioralMutant(
    temp, `descriptor-fd10-writer-accepted-${mode}`, source,
    [
      ['        if duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)', '        if False and duplicate_observation[2]:\n                if duplicate_observation[3]:\n                    die(151)\n                die(152)'],
      ['        if any(observation[3] for observation in observations.values()):\n            die(195)', '        if False and any(observation[3] for observation in observations.values()):\n            die(195)'],
    ],
    '',
    'TestPlanBrokerCPUDescriptorGuardMutantFD10', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\tcase=false_fd10_writer', 'checkpoint_plan_broker_cpu', false,
  );
  compileBehavioralMutant(
    temp, `descriptor-higher-writer-accepted-${mode}`, source,
    '        if any(observation[3] for observation in observations.values()):\n            die(195)',
    '        if False and any(observation[3] for observation in observations.values()):\n            die(195)',
    'TestPlanBrokerCPUDescriptorGuardMutantHigher', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\tcase=false_unrelated_higher_writer', 'checkpoint_plan_broker_cpu', false,
  );
  compileBehavioralMutant(
    temp, `descriptor-wrong-fd10-object-accepted-${mode}`, source,
    '            if duplicate_observation is None or duplicate_observation[:2]!=initial or not duplicate_observation[2] or not duplicate_observation[3] or initial[1]&os.O_ACCMODE!=os.O_WRONLY:',
    '            if False:',
    'TestPlanBrokerCPUDescriptorGuardMutantWrongFD10', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\tcase=true_unrelated_fd10', 'checkpoint_plan_broker_cpu', false,
  );
  compileBehavioralMutant(
    temp, `descriptor-extra-writer-accepted-${mode}`, source,
    '            if any(observation[3] for fd,observation in observations.items() if fd!=DUP_GUARD):',
    '            if False:',
    'TestPlanBrokerCPUDescriptorGuardMutantExtraWriter', '__PLAN_RELAUNCH_DESCRIPTOR_CONTROL_FAILURE__\tcase=true_exact_plus_extra_writer', 'checkpoint_plan_broker_cpu', false,
  );
}

function executeInventory(binary, expected, timeout, optIn = false) {
  const linuxRepo = wslPath(root), linuxBinary = wslPath(binary);
  const selection = `^(${expected.join('|')})$`;
  const shell = [
    'set -eu',
    'repo=$1; binary=$2; selection=$3; duration=$4; test_duration=$5; opt_in=$6',
    'cd -- "$repo"',
    'if [ "$opt_in" = yes ]; then exec env VRAM_PLAN_BROKER_CPU_OPT_IN=I_ACKNOWLEDGE_LOCAL_TRANSIENT_UNIT_EFFECTS timeout --signal=TERM --kill-after=10s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"; fi',
    'exec timeout --signal=TERM --kill-after=10s "$duration" "$binary" -test.v -test.count=1 -test.timeout="$test_duration" -test.run="$selection"',
  ].join('\n');
  // All interpolated values travel as positional arguments; the script is
  // supplied on stdin so PowerShell and WSL do not reinterpret nested quotes.
  const result = spawnSync('wsl.exe', fixedWslTestArgv(optIn, [linuxRepo, linuxBinary, selection, `${timeout}s`, `${timeout - 10}s`, optIn ? 'yes' : 'no']), {
    cwd: root, encoding: 'utf8', input: shell, timeout: (timeout + 30) * 1000, maxBuffer: 8 * 1024 * 1024,
  });
  if (result.error || result.status === null) { preservePrivateWorkspace = true; throw result.error ?? new Error('WSL oracle ended without a confirmed child exit'); }
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0) {
    if (optIn) {
      preservePrivateWorkspace = true;
      const diagnostic = classifyInactiveWaitFailure(output, expected);
      const siteDiagnostic = classifyOptInTestFailureSites(output, expected);
      const stageDiagnostic = classifyTypedFailureStage(output, expected);
      process.stderr.write(`bounded WSL test oracle exited ${result.status ?? 'without a status'}; ${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}\n`);
      throw new Error(`bounded WSL test oracle exited ${result.status ?? 'without a status'}; ${diagnostic}; ${stageDiagnostic}; ${siteDiagnostic}`);
    }
    process.stderr.write(output);
    throw new Error(`bounded WSL test oracle exited ${result.status ?? 'without a status'}`);
  }
  try { exactInventory(output, expected); }
  catch (error) { if (optIn) preservePrivateWorkspace = true; throw error; }
  if (expected.includes(descriptorGuardControlTest)) {
    try { classifyDescriptorGuardControlResult(result); }
    catch (error) { throw new Error(`descriptor guard control inventory rejected: ${error?.message ?? String(error)}`); }
  }
  if (optIn && expected.includes('TestCheckpointPlanRelaunchCPULifecycleSequence')) {
    try { validateUnitHolderControlEvents(output); }
    catch (error) { preservePrivateWorkspace = true; throw error; }
  }
  return output;
}

function withPrivateBinary(mode) {
  requireReviewedCurrentFreeze();
  const prefix = '.tmp-plan-relaunch-verifier-';
  const temp = mkdtempSync(path.join(root, prefix));
  const before = lstatSync(temp);
  try {
    if (mode === '--mode=authority') {
      const wireTest = ['TestPlanRelaunchWireIsCatalogTypedAndRejectsGenericAuthority'];
      const wireBinary = compileLinuxBinary('./internal/wsproto', temp, 'wire.test');
      const wireOutput = executeInventory(wireBinary, wireTest, 60);
      const nodeTests = ['TestCheckpointPlanCatalogRequiresCanonicalApprovedV2Bytes', 'TestPlanRelaunchSharesStopFenceAndRequiresTerminalPriorStep', 'TestPlanRelaunchReceiptRequiresExactOriginalAndFreshIdentity', ...recoveryPolicyTests, 'TestPlanRelaunchQueryTimeWindowIsBounded', 'TestPlanBrokerUnitParserRequiresCompleteFixedProperties'];
      nodeTests.push('TestPlanBrokerRequestHalfCloseUnixStream', 'TestPlanBrokerRequestHalfCloseRejectsWriteFaults');
      const nodeBinary = compileLinuxBinary('./internal/nodeagent', temp, 'authority.test');
      executeInventory(nodeBinary, nodeTests, 90, true);
      if (!wireOutput.includes('PASS')) throw new Error('plan relaunch wire mutant test did not report PASS');
      console.log('checkpoint plan relaunch authority verification passed');
    } else if (mode === '--mode=reconcile') {
      const selected = ['TestPlanRelaunchReceiptRequiresExactOriginalAndFreshIdentity', 'TestPlanRelaunchReceiptReconcilesOnlyPreviouslyAcceptedExpiredIntent', ...recoveryPolicyTests, 'TestPlanRelaunchQueryTimeWindowIsBounded', 'TestPlanBrokerUnitParserRequiresCompleteFixedProperties', 'TestPlanBrokerJobParserUsesExactUnitIdentity', 'TestCheckpointPlanRelaunchCPULifecycleSequence', 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect'];
      const binary = compileLinuxBinary('./internal/nodeagent', temp, 'reconcile.test', 'checkpoint_plan_broker_cpu');
      executeInventory(binary, ['TestPlanBrokerCPUFailureMarkerControlsPure'], 60, false);
      executeInventory(binary, ['TestPlanBrokerCPUDescriptorGuardControls'], 60, false);
      verifyCompiledHolderDiagnosticMutants(temp, 'reconcile');
      verifyCompiledDescriptorGuardMutants(temp, 'reconcile');
      const output = executeInventory(binary, selected, 240, true);
      if (output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__').length !== 2) { preservePrivateWorkspace = true; throw new Error('reconcile fixture did not emit exactly one parent-death EOF positive marker'); }
      verifyCompiledParentDeathMutants(temp, 'reconcile');
      verifyCompiledRequestHalfCloseMutant(temp, 'reconcile');
      console.log('checkpoint plan relaunch reconciliation verification passed');
    } else {
      const selected = ['TestCheckpointPlanRelaunchCPULifecycleSequence', 'TestCheckpointPlanRelaunchCPUStartRequestedCrashNoEffect'];
      const binary = compileLinuxBinary('./internal/nodeagent', temp, 'cpu-sequence.test', 'checkpoint_plan_broker_cpu');
      executeInventory(binary, ['TestPlanBrokerCPUFailureMarkerControlsPure'], 60, false);
      executeInventory(binary, ['TestPlanBrokerCPUDescriptorGuardControls'], 60, false);
      verifyCompiledHolderDiagnosticMutants(temp, 'cpu-sequence');
      verifyCompiledDescriptorGuardMutants(temp, 'cpu-sequence');
      const output = executeInventory(binary, selected, 240, true);
      if (output.split('__PLAN_RELAUNCH_CPU_SEQUENCE_POSITIVE__').length !== 2 || output.split('__PLAN_RELAUNCH_PARENT_DEATH_EOF_POSITIVE__').length !== 2) { preservePrivateWorkspace = true; throw new Error('CPU lifecycle fixture did not emit exactly one required positive marker for each oracle'); }
      verifyCompiledParentDeathMutants(temp, 'cpu-sequence');
      verifyCompiledBehavioralMutants(temp);
      verifyCompiledRequestHalfCloseMutant(temp, 'cpu-sequence');
      console.log('checkpoint plan relaunch CPU sequence verification passed');
    }
  } finally {
    const current = lstatSync(temp);
    if (path.dirname(temp) !== root || !path.basename(temp).startsWith(prefix) || !current.isDirectory() || current.dev !== before.dev || current.ino !== before.ino) {
      throw new Error('private verifier workspace identity changed; preserved it');
    }
    if (preservePrivateWorkspace) {
      console.error(`preserved uncertain private verifier workspace: ${temp}`);
    } else {
      rmSync(temp, { recursive: true, force: true });
    }
  }
}

const recoveryPolicyTests = ['TestPlanRelaunchRecoveryNeverRepeatsAmbiguousStart'];
if (argv[0] === '--mode=source-only') {
  console.log(`checkpoint plan relaunch source-only controls passed: ${sourceControls.expectedPortable.length} recovery policy test(s); Broker58 object-based bounded fd provenance and Broker47 typed branch/cap bootstrap source controls passed; nine-case descriptor behavior and its compiled mutants are source-present but unexecuted; parent-death EOF oracle is source-present but unexecuted; request half-close oracle is source-present but unexecuted; exact 17-path preflight passed; runtime gates not run`);
  process.exit(0);
}

try {
  withPrivateBinary(argv[0]);
} catch (error) {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
}
