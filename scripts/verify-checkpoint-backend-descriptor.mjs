#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const base = '62acc89c26c66076cb72e049f307fbe93b8b9750';
const CPU_WSL_TIMEOUT_MS = 1_050_000;
const CPU_ORCHESTRATOR_TIMEOUT_MS = 1_100_000;
const CPU_LINUX_DEADLINE_SECONDS = 840;
const patchPath = path.join(root, 'patches/llama.cpp', base, '0001-checkpoint-compat-descriptor.patch');
const fixtureDir = path.join(root, 'scripts/checkpoint-compat');
const patchFiles = [
  'include/llama.h',
  'src/llama-context.cpp',
  'src/llama-kv-cache.h',
  'src/llama-kv-cache.cpp',
  'tools/server/server-context.h',
  'tools/server/server-context.cpp',
  'tools/server/server.cpp',
];
const requiredFields = [
  'schemaVersion', 'support', 'architecture', 'sequenceSerializer', 'context', 'kv', 'slots', 'processId', 'authority',
  'nCtx', 'nCtxSeq', 'nBatch', 'nUbatch', 'nSeqMax', 'nRsSeq', 'kvUnified', 'causalAttention', 'rope',
  'originalContext', 'freqBaseBits', 'freqScaleBits', 'yarnExtFactorBits', 'yarnAttnFactorBits', 'yarnBetaFastBits', 'yarnBetaSlowBits',
  'subtype', 'typeK', 'typeV', 'streams', 'cells', 'padding', 'vTransposed', 'rotation', 'layers',
  'k', 'v', 'layer', 'type', 'shape', 'strides', 'rowBytes', 'id', 'contextCapacity',
];

function die(message) {
  console.error(`checkpoint backend descriptor: ${message}`);
  process.exitCode = 1;
}

const FAILURE_SUMMARY_MAX_CHARS = 240;
const CLEANUP_UNCERTAIN_MARKER = 'cleanup uncertain; preserving private workspace';

function formatFailureSummary({ status, error, stdout = '', stderr = '' }) {
  const clean = value => String(value)
    .replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/[\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g, ' ')
    .replace(/(^|[\s"'(=])(?:[A-Za-z]:[\\/]|\/)[^\s"'<>),;]*/g, '$1[path]')
    .replace(/\s+/g, ' ').trim();
  const lines = value => String(value).slice(-65536).split(/\r?\n/).map(line => clean(line));
  const pythonCause = value => lines(value).filter(line => /^(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:Error|Exception|Interrupt|Exit)|SystemExit):/i.test(line)).at(-1);
  const otherCause = value => lines(value).filter(line => /^(?:error:|fatal error:|checkpoint backend descriptor:)/i.test(line)).at(-1);
  const selectedCause = pythonCause(stderr) || pythonCause(stdout) || otherCause(stderr) || otherCause(stdout);
  const cause = selectedCause?.replace(/cleanup uncertain;\s*preserving private workspace\b/i, '').replace(/[;,\s]+$/, '');
  const uncertainCleanup = /cleanup uncertain;\s*preserving private workspace\b/i.test(`${String(stderr).slice(-65536)}\n${String(stdout).slice(-65536)}`);
  const cleanupSuffix = uncertainCleanup ? `; ${CLEANUP_UNCERTAIN_MARKER}` : '';
  const prefixLimit = FAILURE_SUMMARY_MAX_CHARS - cleanupSuffix.length;
  const primary = error
    ? (/timed?\s*out|ETIMEDOUT/i.test(error.message ?? '') ? 'timed out' : `process error: ${clean(error.message).slice(0, 100)}`)
    : status == null ? 'process status unavailable' : `exit ${status}`;
  const prefix = error || status == null ? `${primary}${cause ? `; ${cause}` : ''}` : cause ? `${cause} (exit ${status})` : primary;
  return `${prefix.slice(0, prefixLimit)}${cleanupSuffix}`;
}

function failureOutcome({ status, error }) {
  if (error) return /timed?\s*out|ETIMEDOUT/i.test(error.message ?? '') ? 'timeout' : 'spawn error';
  return status == null ? 'unknown status' : `exit ${status}`;
}

function verifyFailureSummaryControls() {
  const noise = `build-output-${'x'.repeat(4096)}\n`;
  const decisive = formatFailureSummary({ status: 1, stdout: noise, stderr: `Traceback (most recent call last):\nRuntimeError: initialized slot capacity mismatch\u202e\u001b` });
  if (!decisive.startsWith('RuntimeError: initialized slot capacity mismatch') || decisive.length > FAILURE_SUMMARY_MAX_CHARS || /[\u202a-\u202e\u2066-\u2069\u0000-\u001f\u007f-\u009f]/.test(decisive)) {
    throw new Error('failure summary did not frontload a bounded sanitized decisive cause');
  }
  const generic = formatFailureSummary({ status: 1, stdout: noise, stderr: 'unclassified child failure' });
  const uncertain = 'fixture cleanup uncertain; preserving private workspace /home/fixture/private-cache';
  const longCause = formatFailureSummary({ status: 1, stderr: `RuntimeError: ${'K/V global/per-sequence capacity '.repeat(24)} /home/fixture/private-cache\n${uncertain}` });
  const timeout = formatFailureSummary({ status: null, error: Object.assign(new Error('spawnSync timed out'), { code: 'ETIMEDOUT' }), stderr: `RuntimeError: stale output\n${uncertain}` });
  if (generic !== 'exit 1' || !timeout.startsWith('timed out') || !timeout.includes(CLEANUP_UNCERTAIN_MARKER) ||
      longCause.length !== FAILURE_SUMMARY_MAX_CHARS || !longCause.includes(CLEANUP_UNCERTAIN_MARKER) ||
      !longCause.includes('K/V') || !longCause.includes('global/per-sequence') || longCause.includes('/home/fixture')) {
    throw new Error('generic failure, bounded-cause, path, or timeout/cleanup summary control changed');
  }
}

function verifyInventory(transcript, expected) {
  const lines = transcript.split(/\r?\n/);
  const begin = lines.indexOf('CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN');
  const end = lines.indexOf('CHECKPOINT_CONTROL_TRANSCRIPT_END');
  if (begin < 0 || end <= begin || lines.lastIndexOf('CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN') !== begin ||
      lines.lastIndexOf('CHECKPOINT_CONTROL_TRANSCRIPT_END') !== end) return false;
  const events = lines.slice(begin + 1, end);
  return events.length === expected.length * 2 && expected.every((name, index) =>
    events[index * 2] === `RUN ${name}` && events[index * 2 + 1] === `PASS ${name}`);
}

function verifyTranscriptMutants(expected) {
  const wrap = events => ['CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN', ...events, 'CHECKPOINT_CONTROL_TRANSCRIPT_END'].join('\n');
  const good = expected.flatMap(x => [`RUN ${x}`, `PASS ${x}`]);
  const missing = good.slice(2);
  const duplicate = [...good.slice(0, 2), ...good.slice(0, 2), ...good.slice(2)];
  const skipped = [...good.slice(0, 2), `RUN ${expected[1]}`, `SKIP ${expected[1]}`, ...good.slice(4)];
  const failed = [...good.slice(0, 2), `RUN ${expected[1]}`, `FAIL ${expected[1]}`, ...good.slice(4)];
  const malformed = [...good.slice(0, 2), `RUN ${expected[1]}`, `PASS  ${expected[1]}`, ...good.slice(4)];
  const unexpected = [...good, 'SKIP extra-control'];
  const reversed = [...good.slice(0, 2), `PASS ${expected[1]}`, `RUN ${expected[1]}`, ...good.slice(4)];
  return verifyInventory(wrap(good), expected) && !verifyInventory(wrap(missing), expected) &&
    !verifyInventory(wrap(duplicate), expected) && !verifyInventory(wrap(skipped), expected) &&
    !verifyInventory(wrap(failed), expected) && !verifyInventory(wrap(malformed), expected) &&
    !verifyInventory(wrap(unexpected), expected) && !verifyInventory(wrap(reversed), expected);
}

function sourceBoundTimeout(source, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const matches = [...source.matchAll(new RegExp(`^const ${escaped} = ([0-9_]+);$`, 'gm'))];
  if (matches.length !== 1) throw new Error(`runtime timeout constant is missing or ambiguous: ${name}`);
  return Number(matches[0][1].replaceAll('_', ''));
}

function runtimeTimeouts(cpu, orchestrator) {
  const cpuCall = cpu.slice(cpu.indexOf('function call(args, input) {'), cpu.indexOf('function wslPath(value) {'));
  const cpuLaunchStart = cpu.lastIndexOf("const result = spawnSync('wsl.exe'");
  const cpuLaunchEnd = cpu.indexOf('if (result.error || result.status !== 0)', cpuLaunchStart);
  const cpuAdmissionStart = cpu.indexOf('const launchElapsedMs =');
  const cpuLaunch = cpu.slice(cpuAdmissionStart, cpuLaunchEnd);
  const preflightStart = cpu.indexOf('const uid = call(');
  const preflightEnd = cpu.indexOf('const namespaceBootstrap =', preflightStart);
  const preflightCallsSource = cpu.slice(preflightStart, preflightEnd);
  const preflightCalls = (preflightCallsSource.match(/\bcall\(\[/g) ?? []).length +
    (preflightCallsSource.match(/\bwslPath\(/g) ?? []).length;
  const preflightCallFunction = cpuCall.slice(cpuCall.indexOf('function call(args, input) {'));
  const preflightClockStart = cpu.indexOf('function preflightRemainingMs() {');
  const preflightClockEnd = cpu.indexOf('\nfunction call(args, input) {', preflightClockStart);
  const preflightClock = cpu.slice(preflightClockStart, preflightClockEnd);
  const runtimeStart = orchestrator.indexOf('function runtimeMode(which) {');
  const runtimeEnd = orchestrator.indexOf('\nconst mode =', runtimeStart);
  const runtime = orchestrator.slice(runtimeStart, runtimeEnd);
  if (!cpuCall || !cpuLaunch || !runtime ||
      !/timeout:\s*timeout\s*,/.test(preflightCallFunction) ||
      !/Math\.min\(CPU_PREFLIGHT_CALL_TIMEOUT_MS,\s*remaining\)/.test(preflightCallFunction) ||
      !/const remaining = Math\.floor\(preflightDeadline - performance\.now\(\)\)/.test(preflightClock) ||
      !/if\s*\(remaining\s*<=\s*0\)[\s\S]*?cumulative WSL preflight budget exhausted/.test(preflightClock) ||
      !/const cpuStartedAt = performance\.now\(\)/.test(cpu) ||
      !/const preflightDeadline = cpuStartedAt \+ CPU_PREFLIGHT_BUDGET_MS/.test(cpu) ||
      cpu.indexOf('const cpuStartedAt = performance.now()') > cpu.indexOf('const here =') ||
      !/const remaining = preflightRemainingMs\(\)/.test(preflightCallFunction) ||
      cpuAdmissionStart < 0 || cpuLaunchStart < cpuAdmissionStart || cpuLaunchEnd <= cpuLaunchStart ||
      !/timeout:\s*mainWslTimeoutMs\s*,/.test(cpuLaunch) ||
      !/launchElapsedMs\s*=\s*Math\.floor\(performance\.now\(\)\s*-\s*cpuStartedAt\)/.test(cpuLaunch) ||
      !/mainWslTimeoutMs\s*=\s*CPU_WSL_TIMEOUT_MS\s*-\s*launchElapsedMs/.test(cpuLaunch) ||
      !/if\s*\(launchElapsedMs\s*>\s*CPU_PREFLIGHT_BUDGET_MS\)[\s\S]*?private namespace\/build was not launched/.test(cpuLaunch) ||
      !/if\s*\(mainWslTimeoutMs\s*<\s*CPU_MAIN_MIN_REMAINING_MS\)[\s\S]*?private namespace\/build was not launched/.test(cpuLaunch) ||
      cpuLaunch.indexOf('if (launchElapsedMs > CPU_PREFLIGHT_BUDGET_MS)') > cpuLaunch.indexOf("const result = spawnSync('wsl.exe'") ||
      cpuLaunch.indexOf('if (mainWslTimeoutMs < CPU_MAIN_MIN_REMAINING_MS)') > cpuLaunch.indexOf("const result = spawnSync('wsl.exe'") ||
      !/timeout:\s*CPU_ORCHESTRATOR_TIMEOUT_MS\s*,/.test(runtime) || preflightCalls !== 4 ||
      (cpu.match(/spawnSync\('wsl\.exe'/g) ?? []).length !== 2) {
    throw new Error('cumulative preflight and runtime deadlines are not wired before the namespace launch');
  }
  return {
    linux: Number(/overall_deadline = time\.monotonic\(\) \+ (\d+)/.exec(cpu)?.[1]),
    wsl: sourceBoundTimeout(cpu, 'CPU_WSL_TIMEOUT_MS'),
    preflight: sourceBoundTimeout(cpu, 'CPU_PREFLIGHT_BUDGET_MS'),
    preflightCall: sourceBoundTimeout(cpu, 'CPU_PREFLIGHT_CALL_TIMEOUT_MS'),
    preflightCalls,
    minMain: sourceBoundTimeout(cpu, 'CPU_MAIN_MIN_REMAINING_MS'),
    orchestrator: sourceBoundTimeout(orchestrator, 'CPU_ORCHESTRATOR_TIMEOUT_MS'),
  };
}

function validRuntimeBudget(budget) {
  return budget.linux === CPU_LINUX_DEADLINE_SECONDS && budget.wsl === CPU_WSL_TIMEOUT_MS &&
    budget.orchestrator === CPU_ORCHESTRATOR_TIMEOUT_MS &&
    budget.preflight === 30_000 && budget.preflightCall === 10_000 && budget.preflightCalls === 4 &&
    budget.minMain === 900_000 && budget.preflightCall * budget.preflightCalls >= budget.preflight &&
    budget.minMain >= budget.linux * 1000 + 60_000 &&
    budget.preflight + budget.minMain <= budget.wsl &&
    budget.preflight + budget.minMain + 30_000 <= budget.orchestrator &&
    budget.wsl + 30_000 <= budget.orchestrator &&
    budget.wsl < budget.orchestrator && budget.orchestrator < 1200000;
}

function simulateCumulativeLaunch(preflightElapsed, totalBudget, preflightLimit, minMain) {
  if (!Number.isSafeInteger(preflightElapsed) || preflightElapsed < 0 || preflightElapsed > preflightLimit) return null;
  const remaining = totalBudget - preflightElapsed;
  return remaining < minMain ? null : remaining;
}

function verifyRuntimeBudgetMutants(cpu, orchestrator, expected) {
  const launchAtStart = simulateCumulativeLaunch(0, expected.wsl, expected.preflight, expected.minMain);
  const launchAtPreflightLimit = simulateCumulativeLaunch(expected.preflight, expected.wsl, expected.preflight, expected.minMain);
  const exhausted = simulateCumulativeLaunch(expected.preflight + 1, expected.wsl, expected.preflight, expected.minMain);
  const collapsedBudget = simulateCumulativeLaunch(expected.preflight, expected.preflight + expected.minMain - 1, expected.preflight, expected.minMain);
  if (launchAtStart !== expected.wsl || launchAtPreflightLimit !== expected.wsl - expected.preflight || exhausted !== null || collapsedBudget !== null) {
    throw new Error('cumulative deadline positive, exhaustion, or no-launch controls did not distinguish their outcomes');
  }
  const nonRuntimeMutant = orchestrator.replace('timeout: 10000', 'timeout: 500');
  if (nonRuntimeMutant === orchestrator || JSON.stringify(runtimeTimeouts(cpu, nonRuntimeMutant)) !== JSON.stringify(expected)) {
    throw new Error('non-runtime parser timeout mutation affected the runtime budget measurement');
  }
  const collapsedWrapper = orchestrator.replace(
    'const CPU_ORCHESTRATOR_TIMEOUT_MS = 1_100_000;',
    'const CPU_ORCHESTRATOR_TIMEOUT_MS = 1_050_000;',
  );
  if (collapsedWrapper === orchestrator || validRuntimeBudget(runtimeTimeouts(cpu, collapsedWrapper))) {
    throw new Error('runtime wrapper timeout mutant at or below the WSL timeout was accepted');
  }
  const collapsedPreflight = cpu.replace('const CPU_PREFLIGHT_BUDGET_MS = 30_000;', 'const CPU_PREFLIGHT_BUDGET_MS = 10_000;');
  if (collapsedPreflight === cpu || validRuntimeBudget(runtimeTimeouts(collapsedPreflight, orchestrator))) {
    throw new Error('mutated preflight deadline below the reviewed cumulative ceiling was accepted');
  }
  const collapsedMain = cpu.replace('const CPU_WSL_TIMEOUT_MS = 1_050_000;', 'const CPU_WSL_TIMEOUT_MS = 959_999;');
  if (collapsedMain === cpu || validRuntimeBudget(runtimeTimeouts(collapsedMain, orchestrator))) {
    throw new Error('cumulative budget without the minimum post-preflight fixture window was accepted');
  }
  const fixedLaunchTimeout = cpu.replace('timeout: mainWslTimeoutMs, maxBuffer: limit', 'timeout: CPU_WSL_TIMEOUT_MS, maxBuffer: limit');
  let fixedLaunchRejected = false;
  try { runtimeTimeouts(fixedLaunchTimeout, orchestrator); } catch { fixedLaunchRejected = true; }
  if (fixedLaunchTimeout === cpu || !fixedLaunchRejected) {
    throw new Error('fixed full WSL timeout bypassed elapsed-preflight subtraction');
  }
  const noPreflightCutoff = cpu.replace(/if \(launchElapsedMs > CPU_PREFLIGHT_BUDGET_MS\) \{[\s\S]*?\n\}/, '// mutant: omit preflight exhaustion cutoff');
  let cutoffRejected = false;
  try { runtimeTimeouts(noPreflightCutoff, orchestrator); } catch { cutoffRejected = true; }
  if (noPreflightCutoff === cpu || !cutoffRejected) {
    throw new Error('preflight-exhaustion mutant was not rejected before namespace launch');
  }
  const noMinimumWindow = cpu.replace(/if \(mainWslTimeoutMs < CPU_MAIN_MIN_REMAINING_MS\) \{[\s\S]*?\n\}/, '// mutant: omit minimum fixture window');
  let minimumRejected = false;
  try { runtimeTimeouts(noMinimumWindow, orchestrator); } catch { minimumRejected = true; }
  if (noMinimumWindow === cpu || !minimumRejected) {
    throw new Error('minimum-post-preflight-window mutant was not rejected before namespace launch');
  }
}

async function read(rel) {
  return readFile(path.join(root, rel), 'utf8');
}

async function sourceMode() {
  const [patch, builder, generator, cpu] = await Promise.all([
    readFile(patchPath, 'utf8'),
    read('scripts/checkpoint-compat/build-cpu-fixture.sh'),
    read('scripts/checkpoint-compat/make-tiny-llama-gguf.py'),
    read('scripts/checkpoint-compat/verify-cpu-descriptor.mjs'),
  ]);
  const orchestrator = await readFile(fileURLToPath(import.meta.url), 'utf8');
  verifyFailureSummaryControls();
  const helperStart = cpu.indexOf('function formatFailureSummary(');
  const helperEnd = cpu.indexOf('\nfunction failureOutcome(', helperStart);
  const selfTestCall = cpu.indexOf('verifyFailureSummaryControls();');
  const firstWslCall = cpu.indexOf('const uid = call(');
  if (helperStart < 0 || helperEnd <= helperStart || selfTestCall < 0 || firstWslCall <= selfTestCall ||
      !cpu.includes('formatFailureSummary({ status: result.status, error: result.error, stdout: result.stdout, stderr: result.stderr })')) {
    throw new Error('CPU wrapper does not self-test and use its bounded failure formatter');
  }
  const helperFormatter = runInNewContext(`const FAILURE_SUMMARY_MAX_CHARS = 240;\nconst CLEANUP_UNCERTAIN_MARKER = 'cleanup uncertain; preserving private workspace';\n${cpu.slice(helperStart, helperEnd)}\nformatFailureSummary`, Object.create(null));
  if (typeof helperFormatter !== 'function') throw new Error('bounded CPU formatter extraction did not expose the exact helper function');
  const cleanupUncertain = 'fixture cleanup uncertain; preserving private workspace /home/fixture/private-cache';
  const helperFailure = helperFormatter({ status: 1, stdout: 'x'.repeat(8192), stderr: `Traceback (most recent call last):\nRuntimeError: initialized context capacity mismatch\n${cleanupUncertain}` });
  const helperErrorEnvelope = `Error: fixture orchestration exit 1: ${helperFailure}`;
  const layeredFailure = formatFailureSummary({ status: 1, stdout: `build noise ${'x'.repeat(8192)}\n`, stderr: `${helperErrorEnvelope}\n${cleanupUncertain}` });
  const helperTimeout = helperFormatter({ status: null, error: Object.assign(new Error('spawnSync timed out'), { code: 'ETIMEDOUT' }), stderr: 'RuntimeError: stale output' });
  if (!helperFailure.startsWith('RuntimeError: initialized context capacity mismatch') || helperFailure.length > FAILURE_SUMMARY_MAX_CHARS ||
      !helperFailure.includes('cleanup uncertain; preserving private workspace') || helperFailure.includes('/home/fixture') ||
      !layeredFailure.startsWith('Error: fixture orchestration exit 1:') || !layeredFailure.includes('RuntimeError: initialized context capacity mismatch') ||
      !layeredFailure.includes('cleanup uncertain; preserving private workspace') || layeredFailure.length > FAILURE_SUMMARY_MAX_CHARS || layeredFailure.includes('/home/fixture') ||
      layeredFailure.indexOf('RuntimeError:') > layeredFailure.indexOf('cleanup uncertain;') ||
      !helperTimeout.startsWith('timed out')) {
    throw new Error('actual CPU and outer failure formatters did not preserve bounded decisive and timeout diagnostics');
  }
  const actualFiles = [...patch.matchAll(/^diff --git a\/([^\s]+) b\/([^\s]+)$/gm)].map(match => {
    if (match[1] !== match[2]) throw new Error('patch contains a rename or cross-path hunk');
    return match[1];
  });
  if (new Set(actualFiles).size !== actualFiles.length ||
      JSON.stringify([...actualFiles].sort()) !== JSON.stringify([...patchFiles].sort())) {
    throw new Error('patch upstream path inventory is not the exact seven-file allowlist');
  }
  const kvGetSizeContext = /@@ -1203,6 \+1203,34 @@ uint32_t llama_kv_cache::get_size\(\) const \{\r?\n     return cells\.size\(\);/;
  if (!kvGetSizeContext.test(patch) || patch.includes('return v_cells.size();')) {
    throw new Error('KV-cache patch context does not match the pinned get_size implementation');
  }
  const syntax = spawnSync('git', ['apply', '--numstat', patchPath], {
    cwd: root, encoding: 'utf8', timeout: 10000, maxBuffer: 65536, windowsHide: true,
  });
  if (syntax.error || syntax.status !== 0) throw new Error(`patch syntax parser rejected the diff: ${syntax.error?.message ?? syntax.stderr.trim()}`);
  const parsed = syntax.stdout.trim().split(/\r?\n/).map(line => {
    const match = /^(\d+)\t(\d+)\t(.+)$/.exec(line);
    if (!match) throw new Error('patch syntax parser returned an unexpected stat row');
    return { added: Number(match[1]), removed: Number(match[2]), file: match[3] };
  });
  if (parsed.length !== patchFiles.length || parsed.some(row => row.removed !== 0) ||
      JSON.stringify(parsed.map(row => row.file).sort()) !== JSON.stringify([...patchFiles].sort())) {
    throw new Error('parsed patch stats do not match the insertion-only upstream allowlist');
  }
  if (!patch.startsWith(`From ${base} `) || !patch.includes(`Pinned base: ${base}`)) throw new Error('patch is not bound to the pinned upstream commit');
  if (!patch.includes('LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR=1') || !patch.includes('schemaVersion\\":1') ||
      !patch.includes('llama-state-seq-62acc89-v1')) throw new Error('fixed opt-in or versioned schema/serializer is missing');
  const exactKey = field => patch.includes(String.raw`\"${field}\"`) || patch.includes(`"${field}"`);
  for (const field of requiredFields) {
    if (!exactKey(field)) throw new Error(`exact descriptor JSON key missing from patch: ${field}`);
  }
  const sourceInvariant = candidate => requiredFields.every(field => candidate.includes(String.raw`\"${field}\"`) || candidate.includes(`"${field}"`)) &&
    candidate.includes('std::getenv("LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR")') && candidate.includes('schemaVersion\\":1');
  if (!sourceInvariant(patch) || sourceInvariant(patch.replace(String.raw`\"rowBytes\":`, String.raw`\"rowBytesMutant\":`)) ||
      sourceInvariant(patch.replace('std::getenv("LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR")', 'std::getenv("LLAMA_CHECKPOINT_MUTANT")'))) {
    throw new Error('exact field/opt-in source mutants failed to break the source contract');
  }
  const canonicalSourceInvariant = candidate => {
    const canonicalStart = candidate.indexOf('json checkpoint_compat_canonicalize_json(const json & value)');
    const canonicalBodyEnd = candidate.indexOf('\n+}', candidate.indexOf('\n+    return value;', canonicalStart));
    const descriptorStart = candidate.indexOf('json server_context::get_checkpoint_compat_descriptor() const {');
    const descriptorEnd = candidate.indexOf('\n server_response_reader server_context::get_response_reader()', descriptorStart);
    if (canonicalStart < 0 || canonicalBodyEnd <= canonicalStart || descriptorStart < 0 || descriptorEnd <= descriptorStart) return false;
    const canonicalizer = candidate.slice(canonicalStart, canonicalBodyEnd);
    const descriptor = candidate.slice(descriptorStart, descriptorEnd);
    return [
      'std::sort(keys.begin(), keys.end());', 'json canonical = json::object();',
      'canonical[key] = checkpoint_compat_canonicalize_json(value.at(key));', 'json canonical = json::array();',
      'for (const auto & item : value)', 'canonical.push_back(checkpoint_compat_canonicalize_json(item));',
    ].every(token => canonicalizer.includes(token)) && [
      'json canonical = checkpoint_compat_canonicalize_json(result);',
      'canonical.dump().size() > sizeof(bytes) - 1', 'return canonical;',
    ].every(token => descriptor.includes(token));
  };
  const unsortedObjectMutant = patch.replace('std::sort(keys.begin(), keys.end());', 'std::reverse(keys.begin(), keys.end());');
  const shallowObjectMutant = patch.replace('canonical[key] = checkpoint_compat_canonicalize_json(value.at(key));', 'canonical[key] = value.at(key);');
  const shallowArrayMutant = patch.replace('canonical.push_back(checkpoint_compat_canonicalize_json(item));', 'canonical.push_back(item);');
  const unboundedDescriptorMutant = patch.replace('canonical.dump().size() > sizeof(bytes) - 1', 'canonical.dump().size() > sizeof(bytes) + 1');
  if (!canonicalSourceInvariant(patch) || canonicalSourceInvariant(unsortedObjectMutant) ||
      canonicalSourceInvariant(shallowObjectMutant) || canonicalSourceInvariant(shallowArrayMutant) ||
      canonicalSourceInvariant(unboundedDescriptorMutant)) {
    throw new Error('recursive canonical object/ordered-array and final-size source controls failed');
  }
  if (!patch.includes('#include "llama-kv-cache.h"') ||
      !patch.includes('json::parse_no_throw(std::string(bytes))') ||
      !patch.includes('return checkpoint_compat_enabled_for_process();') ||
      (patch.match(/std::getenv\("LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR"\)/g) ?? []).length !== 1 ||
      (patch.match(/if \(checkpoint_compat_enabled_for_process\(\)\)/g) ?? []).length !== 3) {
    throw new Error('cache subtype include, bounded parser, and shared startup-captured route guard are incomplete');
  }
  for (const marker of ['LLM_ARCH_LLAMA', 'LLAMA_CONTEXT_TYPE_DEFAULT', 'get_n_swa() != 0', 'get_attn_rot_k()', 'get_attn_rot_v()', 'get_v_trans()',
    'get_n_stream()', 'get_n_pad()', 'get_layer_ids()', 'get_k_storage(id)', 'get_v_storage(id)',
    'checkpoint_compat_enabled()', 'post_props', 'post_lora_adapters', 'has_adapter', 'processId']) {
    if (!patch.includes(marker)) throw new Error(`fail-closed implementation marker missing: ${marker}`);
  }
  const boundedPatchCommands = [
    'timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" apply --check "$patch_file"',
    'timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" apply "$patch_file"',
    'actual_patch_names=$(git -C "$source_dir" diff --name-only)',
  ];
  const expectedStatusMatch = /expected_patch_status=\$'([^']+)'/.exec(builder);
  const expectedNamesMatch = /expected_patch_names=\$'([^']+)'/.exec(builder);
  const builderStatusPaths = expectedStatusMatch?.[1].split(String.raw`\n`).map(line => /^ M (.+)$/.exec(line)?.[1]);
  const builderDiffPaths = expectedNamesMatch?.[1].split(String.raw`\n`);
  const exactBuilderPaths = [...patchFiles].sort();
  if (boundedPatchCommands.some(command => !builder.includes(command)) ||
      JSON.stringify(builderStatusPaths) !== JSON.stringify(exactBuilderPaths) ||
      JSON.stringify(builderDiffPaths) !== JSON.stringify(exactBuilderPaths) ||
      !builder.includes(base) || !builder.includes('GGML_CUDA=OFF') ||
      !builder.includes('id -u') || !builder.includes('private root owner mismatch')) throw new Error('pinned, unprivileged CPU build contract is incomplete');
  const imports = [...generator.matchAll(/^import ([a-zA-Z_][a-zA-Z0-9_]*)/gm)].map(m => m[1]);
  if (imports.some(name => !['json', 'pathlib', 'struct', 'sys'].includes(name)) || imports.length !== 4) {
    throw new Error('synthetic GGUF generator is not standard-library-only');
  }
  for (const marker of ['GGUF', 'GGML_TYPE_F32', 'tokenizer.ggml.tokens', 'llama.attention.head_count',
    'blk.0.attn_q.weight', 'deterministic, small, nonzero pattern', 'headDimension', 'vTransposed',
    'defaultCacheTypeK', 'ropeFrequencyBase', 'ropeScalingType', 'yarnExtFactor', 'yarnBetaFast']) {
    if (!generator.includes(marker)) throw new Error(`synthetic fixture coverage missing: ${marker}`);
  }
  for (const marker of ['127.0.0.1', '/proc/net/tcp', 'listener is not held solely', 'proc_start',
    'canonical JSON', 'supported-positive-first', 'initialized-unsupported-context', 'startup-optout',
    'LLAMA_ATTN_ROT_DISABLE', '--rope-freq-scale', 'request-adapter-rejected', 'parallel-slot-capacity-variant',
    'rotation-enabled-quantized', 'compiled-mutant-rowbytes-rejected', 'compiled-mutant-optin-rejected',
    'CHECKPOINT_CONTROL_TRANSCRIPT_BEGIN', 'CHECKPOINT_CONTROL_TRANSCRIPT_END', 'FAIL',
    '--cache-type-k', '--cache-type-v', '--flash-attn',
    "guard = 'if (checkpoint_compat_enabled_for_process()) {'", 'compiled_mutant_lora_guard', 'build_server', 'start_new_session=True', 'os.killpg',
    'two-stage per-sequence padding', 'initialized K/V cache types differ from exact fixture launch options',
    'actual V transposition or rotation flags are absent/malformed',
    'rowBytes positive-control descriptor endpoint was not live', 'expected_strides',
    'finally:', 'rm -rf -- "$work"', '.fixture-safe-to-clean', 'cleanup uncertain; preserving private workspace']) {
    if (!cpu.includes(marker)) throw new Error(`CPU fixture safety or control missing: ${marker}`);
  }
  const portMarkerStart = cpu.indexOf('def read_port_marker(name, until):');
  const portMarkerEnd = cpu.indexOf('\ndef assert_port_absent(', portMarkerStart);
  const portMarkerReader = portMarkerStart < 0 || portMarkerEnd <= portMarkerStart ? '' : cpu.slice(portMarkerStart, portMarkerEnd);
  const fixedPortWriterInvariant = candidate => [
    "port=f'{s.getsockname()[1]:05d}'.encode('ascii')", 'written=os.write(f,port)', 'if written != 5:',
    'os.fsync(f); os.close(f)',
  ].every(token => candidate.includes(token));
  const fixedPortReaderInvariant = candidate => [
    'while time.monotonic() < until:', 'dir_fd=work_fd', 'os.O_NOFOLLOW', 'except FileNotFoundError:',
    'time.sleep(min(0.025, max(0.0, until - time.monotonic())))', 'marker_identity = identity',
    'marker_path = os.stat(name, dir_fd=work_fd, follow_symlinks=False)',
    'path_after = os.stat(name, dir_fd=work_fd, follow_symlinks=False)',
    'marker_path.st_ino) != identity', 'path_after.st_ino) != identity',
    'marker_stat.st_nlink != 1', 'marker_stat.st_uid != 1000', 'marker_stat.st_mode & 0o077',
    'held_after.st_nlink != 1', 'held_after.st_uid != 1000', 'held_after.st_mode & 0o077',
    'marker_stat.st_size > 5', 'raw = os.read(marker_fd, 6)', 'len(raw) > 5 or held_after.st_size > 5',
    'if held_after.st_size == 5 and len(raw) == 5:', 'not raw.isdigit()', '1 <= int(raw) <= 65535',
    'return int(raw)',
  ].every(token => candidate.includes(token)) &&
    candidate.indexOf('if held_after.st_size == 5 and len(raw) == 5:') < candidate.indexOf('if not raw.isdigit()') &&
    candidate.indexOf('if not raw.isdigit()') < candidate.indexOf('return int(raw)') &&
    (candidate.match(/return int\(raw\)/g) ?? []).length === 1 &&
    !/if len\(raw\) != 5:[\s\S]{0,160}raise RuntimeError/.test(candidate) &&
    !/if len\(raw\) < 5:[\s\S]{0,160}raise RuntimeError/.test(candidate);
  const fixedPortMarkerCalls = [...cpu.matchAll(/read_port_marker\('[^']+\.port', min\(overall_deadline, time\.monotonic\(\) \+ 5\)\)/g)];
  if (!fixedPortWriterInvariant(cpu) ||
      fixedPortWriterInvariant(cpu.replace("port=f'{s.getsockname()[1]:05d}'.encode('ascii')", "port=str(s.getsockname()[1]).encode('ascii')")) ||
      !fixedPortReaderInvariant(portMarkerReader) ||
      fixedPortReaderInvariant(portMarkerReader.replace('while time.monotonic() < until:', 'if time.monotonic() < until:')) ||
      fixedPortReaderInvariant(portMarkerReader.replace('held_after.st_size == 5', '0 < held_after.st_size <= 5')) ||
      fixedPortReaderInvariant(portMarkerReader.replace(
        'raw = os.read(marker_fd, 6)',
        "raw = os.read(marker_fd, 6)\n            if len(raw) < 5: raise RuntimeError('cleanup control listener marker is malformed')",
      )) ||
      fixedPortReaderInvariant(portMarkerReader
        .replace('if held_after.st_size == 5 and len(raw) == 5:', 'if held_after.st_size == 5:')
        .replace('if not raw.isdigit():', "if len(raw) != 5: raise RuntimeError('cleanup control listener marker is malformed')\n                if not raw.isdigit():")) ||
      fixedPortReaderInvariant(portMarkerReader.replace('and len(raw) == 5:', 'and len(raw) >= 1:')) ||
      fixedPortMarkerCalls.length !== 2) {
    throw new Error('listener markers must use exact five-digit publication and bounded held-dirfd readiness with rejecting width/wait mutants');
  }
  for (const marker of [
    'overall_deadline = time.monotonic() + 840', 'signal.pidfd_send_signal(child_pidfd, signal.SIGKILL)',
    "'--user', '--map-current-user', '--mount', '--propagation', 'private', '--pid', '--fork', '--kill-child=KILL', '--mount-proc'",
    'PR_SET_PDEATHSIG', 'supervisor_pidfd, original_parent_pidfd, work_fd',
    'os.getpid() != 1 or os.getuid() != 1000 or os.getgid() != 1000',
    "uid_rows != [['1000', '1000', '1']]", "gid_rows != [['1000', '1000', '1']]",
    'expected_parent_start', 'preexec_fn=pdeathsig_before_exec', 'preexec_fn=pdeath',
    'parent_child_start', 'proc_start(parent_child_pid)',
    'socket.SCM_RIGHTS', 'socket.MSG_CMSG_CLOEXEC', 'import array', 'os.pidfd_open(proc.pid,0)', 'assert_pidfds_terminal',
    'os.memfd_create', 'fcntl.F_ADD_SEALS', 'fcntl.F_SEAL_WRITE', 'stdin=script_fd',
    'short pidfd evidence transfer', "marker == b'running'", 'held_after.st_size == 7',
    'socket.MSG_TRUNC | socket.MSG_CTRUNC', 'len(received) != 1',
    'signal.pidfd_send_signal(timeout_fd, signal.SIGKILL)', 'signal.pidfd_send_signal(launcher_fd, signal.SIGKILL)',
    'sentinel_poll', 'assert_port_live', 'assert_descendant_marker',
    '.fixture-supervisor-complete', 'os.fstat(work_fd)',
    'os.close(child_pidfd)', "pathlib.Path('/proc/self/mountinfo')",
    'CHECKPOINT_CLEANUP_TIMEOUT_CONTROL_PASS', 'CHECKPOINT_PARENT_DEATH_CONTROL_PASS',
    'TERM-resistant detached descendant', 'assert_port_absent', 'wait_terminal_parent', 'sentinel_pdeath', 'launcher_pdeath',
  ]) {
    if (!cpu.includes(marker)) throw new Error(`independent Linux namespace/deadline cleanup contract missing: ${marker}`);
  }
  const sealedShellStart = cpu.indexOf('const script = String.raw`');
  const sealedShell = cpu.slice(sealedShellStart, cpu.indexOf("const result = spawnSync('wsl.exe'", sealedShellStart));
  const innerBodyStart = sealedShell.indexOf("<<'INNER'\n");
  const innerBodyEnd = sealedShell.indexOf('\nINNER', innerBodyStart + 1);
  const sealedInnerBash = innerBodyStart < 0 || innerBodyEnd < 0 ? '' : sealedShell.slice(innerBodyStart, innerBodyEnd);
  const positionalInit = 'builder=$1\npatch_file=$2\ngenerator=$3\nmode=$4';
  const validInnerShellBindings = candidate => {
    const initialized = candidate.indexOf(positionalInit);
    const firstBuilderUse = candidate.indexOf('bash "$builder" "$work" "$patch_file" "$work/provenance.json"');
    return initialized >= 0 && firstBuilderUse >= 0 && initialized < firstBuilderUse &&
      candidate.includes('export CHECKPOINT_FIXTURE_ROOT="$work"') && candidate.includes('export CHECKPOINT_FIXTURE_MODE="$mode"');
  };
  for (const marker of [
    'builder, patch_file, generator, mode = sys.argv[3:7]',
    'builder, patch_file, generator, mode = sys.argv[7:11]',
    'str(work), json.dumps(outer_namespaces), builder, patch_file, generator, fixture_mode',
    "['/bin/bash', '--noprofile', '--norc', '-s', '--', builder, patch_file, generator, mode]",
    'child_env = os.environ.copy()',
    'export CHECKPOINT_FIXTURE_ROOT="$work"',
    'export CHECKPOINT_FIXTURE_MODE="$mode"',
    "'--', builderWsl, patchWsl, generatorWsl, mode],",
  ]) {
    if (!cpu.includes(marker)) throw new Error(`sealed Bash positional/env pass-through missing: ${marker}`);
  }
  if (!validInnerShellBindings(sealedInnerBash) || validInnerShellBindings(sealedInnerBash.replace(positionalInit, ''))) {
    throw new Error('sealed inner Bash does not initialize its exact positional paths/mode before first use');
  }
  const budget = runtimeTimeouts(cpu, orchestrator);
  if (!validRuntimeBudget(budget)) {
    throw new Error('Windows wrapper deadlines do not strictly exceed the bounded Linux fixture deadline');
  }
  verifyRuntimeBudgetMutants(cpu, orchestrator, budget);
  if (cpu.includes('kill -KILL "$fixture_pid"') || cpu.includes('os.killpg(fixture_pid')) {
    throw new Error('fixture cleanup may not use reusable PID or process-group authority');
  }
  if (cpu.indexOf("print('RUN ' + name, flush=True)") < 0 ||
      cpu.indexOf("print('RUN ' + name, flush=True)") > cpu.indexOf('result = action()')) {
    throw new Error('fixture must emit RUN before each control action');
  }
  const controls = ['supported-positive-first', 'context-padding-variant', 'rope-effective-variant',
    'rotation-enabled-quantized', 'rotation-disabled-quantized', 'props-mutation-rejected',
    'lora-mutation-rejected', 'request-adapter-rejected', 'parallel-slot-capacity-variant',
    'initialized-unsupported-context', 'startup-optout', 'compiled-mutant-rowbytes-rejected',
    'compiled-mutant-optin-rejected', 'compiled-mutant-lora-guard-rejected', 'exact-run-pass-inventory'];
  if (!verifyTranscriptMutants(controls)) throw new Error('transcript inventory mutants were not rejected');
  const checkoutPath = "source = root / 'source' / relative";
  const mutantFunction = (startToken, endToken) => {
    const start = cpu.indexOf(startToken);
    const end = cpu.indexOf(endToken, start);
    return start < 0 || end <= start ? '' : cpu.slice(start, end);
  };
  const checkoutPathInvariant = body =>
    (body.match(/source = root \/ 'source' \/ relative/g) ?? []).length === 1 &&
    !body.includes('source = root / relative');
  const rowBytesMutantFunction = mutantFunction('def compiled_mutant(relative, old, new, kind):', '\ndef compiled_mutant_lora_guard():');
  const loraMutantFunction = mutantFunction('def compiled_mutant_lora_guard():', '\ndef stop_on_signal(');
  if (!checkoutPathInvariant(rowBytesMutantFunction) || !checkoutPathInvariant(loraMutantFunction) ||
      checkoutPathInvariant(rowBytesMutantFunction.replace(checkoutPath, 'source = root / relative')) ||
      checkoutPathInvariant(loraMutantFunction.replace(checkoutPath, 'source = root / relative'))) {
    throw new Error('both compiled C++ mutants must edit only their private pinned source checkout; root-relative mutants must be rejected');
  }
  const markerStart = cpu.indexOf('def assert_descendant_marker(name, until):');
  const markerEnd = cpu.indexOf('\ndef make_control_script(', markerStart);
  const markerBody = markerStart < 0 || markerEnd <= markerStart ? '' : cpu.slice(markerStart, markerEnd);
  const markerReadinessInvariant = candidate => [
    'while time.monotonic() < until:', 'dir_fd=work_fd', 'os.O_NOFOLLOW', 'except FileNotFoundError:',
    'time.sleep(min(0.025, max(0.0, until - time.monotonic())))',
    'marker_identity = identity', 'path_stat.st_ino) != identity',
    'held_after.st_ino) != identity', "marker == b'running'", 'marker_stat.st_nlink != 1',
    'marker_stat.st_uid != 1000', 'marker_stat.st_mode & 0o077', 'held_after.st_size == 7',
    'held_after.st_nlink != 1', 'held_after.st_uid != 1000', 'held_after.st_mode & 0o077',
  ].every(token => candidate.includes(token));
  const markerDeadlineCalls = [...cpu.matchAll(/assert_descendant_marker\('[^']+\.descendant', min\(overall_deadline, time\.monotonic\(\) \+ 5\)\)/g)];
  if (!markerReadinessInvariant(markerBody) || markerReadinessInvariant(markerBody.replace('while time.monotonic() < until:', 'if time.monotonic() < until:')) ||
      markerDeadlineCalls.length !== 2) {
    throw new Error('descendant marker readiness must be a bounded exact-dirfd/inode/content observation, with a rejecting no-wait source mutant');
  }
  const digest = createHash('sha256').update(patch).digest('hex');
  console.log(`pinned patch ${digest}; upstream allowlist ${actualFiles.length}; source and transcript controls parsed`);
  console.log('checkpoint backend descriptor source syntax verified; clean-base applicability is deferred to the isolated pinned G2 apply check');
  console.log('checkpoint backend descriptor source verification passed');
}

function runtimeMode(which) {
  const helper = path.join(fixtureDir, 'verify-cpu-descriptor.mjs');
  const arg = which === 'cpu' ? [] : ['--controls'];
  const result = spawnSync(process.execPath, [helper, ...arg], {
    cwd: root, encoding: 'utf8', timeout: CPU_ORCHESTRATOR_TIMEOUT_MS, maxBuffer: 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    const summary = formatFailureSummary({ status: result.status, error: result.error, stdout: result.stdout, stderr: result.stderr });
    throw new Error(`isolated CPU verifier ${failureOutcome(result)}: ${summary}`);
  }
  const expected = which === 'cpu' ? ['initialized-supported-descriptor'] : [
    'supported-positive-first', 'context-padding-variant', 'rope-effective-variant', 'rotation-enabled-quantized',
    'rotation-disabled-quantized', 'props-mutation-rejected', 'lora-mutation-rejected', 'request-adapter-rejected',
    'parallel-slot-capacity-variant', 'initialized-unsupported-context', 'startup-optout',
    'compiled-mutant-rowbytes-rejected', 'compiled-mutant-optin-rejected', 'compiled-mutant-lora-guard-rejected',
    'exact-run-pass-inventory',
  ];
  if (!verifyInventory(result.stdout, expected)) throw new Error('CPU verifier did not emit the exact ordered RUN/PASS transcript');
  if (which === 'controls' && (!result.stdout.includes('CHECKPOINT_CLEANUP_TIMEOUT_CONTROL_PASS') ||
      !result.stdout.includes('CHECKPOINT_PARENT_DEATH_CONTROL_PASS'))) {
    throw new Error('CPU cleanup controls did not prove timeout and parent-death descendant termination');
  }
  const success = which === 'cpu' ? 'checkpoint backend descriptor CPU verification passed' : 'checkpoint backend descriptor controls verification passed';
  if (!result.stdout.includes(success)) throw new Error('CPU verifier omitted its decisive result token');
  console.log(success);
}

const mode = process.argv.find(arg => arg.startsWith('--mode='))?.slice('--mode='.length);
try {
  if (mode === 'source') await sourceMode();
  else if (mode === 'cpu') runtimeMode('cpu');
  else if (mode === 'controls') runtimeMode('controls');
  else throw new Error('expected exactly one of --mode=source, --mode=cpu, or --mode=controls');
} catch (error) {
  die(error.message);
}
