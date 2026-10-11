#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { runInNewContext } from 'node:vm';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const patchPath = path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0002-initialized-shared-pool.patch');
const basePatchPath = path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0001-checkpoint-compat-descriptor.patch');
const frozen = [
  ['patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0001-checkpoint-compat-descriptor.patch', 15156, 'dee4639091787c4ea435b9200b38c36d8db68521d968cbd5a7544dd80cc15f71'],
  ['scripts/checkpoint-compat/build-cpu-fixture.sh', 4380, '88363153ddf8bd36751414501e7733a8f55923bc571560934bc73976f0cbf633'],
  ['scripts/checkpoint-compat/make-tiny-llama-gguf.py', 5728, '1f97f41616e0de8a633196d0e1c6b013adcb7e4008c9863df2514c16fb49ef41'],
  ['scripts/checkpoint-compat/verify-cpu-descriptor.mjs', 65157, 'f3fa2c7e99baf0d0df8ea1a1ad0fd64db1c3f156738006fb5074681bcd48f116'],
  ['scripts/verify-checkpoint-backend-descriptor.mjs', 41595, '36ed9d8846397afa829bca6f00ce48c93f57cd3d8e1d5c5b1429cd0eca3bf8cb'],
];
const allowed = new Set([
  'include/llama.h', 'src/llama-context.cpp', 'tools/server/server-task.h',
  'tools/server/server-context.h', 'tools/server/server-context.cpp', 'tools/server/server.cpp',
  'tools/server/server-queue.h', 'tools/server/server-queue.cpp',
]);
const requiredNames = [
  'initialized-zero-pool',
  'four-retained-distinct-sequences', 'busy-clear-rejected-unchanged',
  'wrong-pool-epoch-rejected-unchanged', 'wrong-slot-epoch-rejected-unchanged',
  'selective-clear-preserves-other-sequences', 'clear-replay-rejected',
  'load-restore-erase-clear-epoch-fence', 'uncapped-short-to-long-same-worker',
  'same-process-listener-incarnation', 'opt-out-default-off', 'nonunified-rejected',
  'slot-cap-long-context-rejected',
];
const expectedScenarioInventory = [
  'initialized-zero-pool',
  'four-retained-distinct-sequences', 'busy-clear-rejected-unchanged',
  'wrong-pool-epoch-rejected-unchanged', 'wrong-slot-epoch-rejected-unchanged',
  'selective-clear-preserves-other-sequences', 'clear-replay-rejected',
  'load-restore-erase-clear-epoch-fence', 'uncapped-short-to-long-same-worker',
  'same-process-listener-incarnation', 'opt-out-default-off', 'nonunified-rejected',
  'slot-cap-long-context-rejected',
];

function assert(ok, message) { if (!ok) throw new Error(message); }
function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function read(rel) { return readFileSync(path.join(repo, rel)); }
function has(text, pattern) { return pattern.test(text); }

const compilerSourceFiles = [
  'include/llama.h', 'src/llama-context.cpp', 'tools/server/server-task.h',
  'tools/server/server-context.h', 'tools/server/server-context.cpp', 'tools/server/server.cpp',
  'tools/server/server-queue.h', 'tools/server/server-queue.cpp',
];
const compilerErrorClasses = ['missing_member', 'missing_symbol', 'type_mismatch', 'syntax_error', 'other_compile_error'];
const sharedPoolBuildPhases = Object.freeze(['base_builder', 'apply_check', 'apply_0002', 'source_union', 'cmake_rebuild', 'provenance_write']);
const sharedPoolStepGuard = [
  'run_shared_pool_step() {',
  '  local phase=$1 status',
  '  shift',
  '  case "$phase" in',
  '    base_builder|apply_check|apply_0002|source_union|cmake_rebuild|provenance_write) ;;',
  '    *) exit 125 ;;',
  '  esac',
  '  if "$@"; then',
  '    return 0',
  '  else',
  '    status=$?',
  "    printf 'SHARED_POOL_STEP_FAIL:%s:%s\\n' \"$phase\" \"$status\" >&2",
  '    exit "$status"',
  '  fi',
  '}',
].join('\n');
const sourceUnionFailureGuard = String.raw`if actual_union=$(git -C "$work/source" diff --name-only | tr "\n" "|" | sed "s/|$//"); then :; else status=$?; printf 'SHARED_POOL_STEP_FAIL:source_union:%s\n' "$status" >&2; exit "$status"; fi`;
const cleanupUncertainMarker = 'cleanup uncertain; preserving private workspace';
const g2FailureSummaryMaxChars = 240;

function classifyCompilerCause(input) {
  const lines = String(input).slice(-65536).split(/\r?\n/).reverse();
  for (const line of lines) {
    for (const sourcePath of compilerSourceFiles) {
      const escaped = sourcePath.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replaceAll('/', '[\\\\/]');
      const match = line.match(new RegExp(`${escaped}:(\\d+)(?::\\d+)?:\\s*(?:fatal\\s+)?error:\\s*(.*)$`, 'i'));
      if (!match) continue;
      const lineNumber = Number(match[1]);
      if (!Number.isInteger(lineNumber) || lineNumber < 1 || lineNumber > 100000) continue;
      const body = match[2].toLowerCase();
      const category = /no member named|has no member named|is not a member/.test(body) ? 'missing_member' :
        /not declared|undeclared|undefined reference|unknown type name|does not name a type/.test(body) ? 'missing_symbol' :
        /cannot convert|incompatible|invalid conversion|cannot initialize|no viable conversion|cannot bind|ambiguous/.test(body) ? 'type_mismatch' :
        /expected .*?(?:before|token|\x27;\x27)|stray .*?(?:\\|character)|parse error/.test(body) ? 'syntax_error' :
        'other_compile_error';
      return `compile_error ${sourcePath}:${lineNumber} ${category}`;
    }
  }
  return '';
}

function summarizeCpuFailure({ status, error, stdout = '', stderr = '' }) {
  const raw = `${String(stderr).slice(-65536)}\n${String(stdout).slice(-65536)}`;
  const uncertain = /cleanup uncertain;\s*preserving private workspace/i.test(raw);
  const statusLabel = error && /timed?\s*out|ETIMEDOUT/i.test(`${error.code || ''} ${error.message || ''}`) ? 'timeout' :
    error ? 'spawn_error' : Number.isInteger(status) ? `exit_${status}` : 'status_unavailable';
  const compile = classifyCompilerCause(raw);
  const orchestration = raw.match(/^Error: fixture orchestration (?:timeout|spawn error|unknown status|exit \d+): ([^\r\n]+)$/m)?.[1] || '';
  const compileSummary = orchestration.match(/^(compile_error (?:include\/llama\.h|src\/llama-context\.cpp|tools\/server\/server-task\.h|tools\/server\/server-context\.h|tools\/server\/server-context\.cpp|tools\/server\/server\.cpp|tools\/server\/server-queue\.h|tools\/server\/server-queue\.cpp):[1-9]\d{0,4} (?:missing_member|missing_symbol|type_mismatch|syntax_error|other_compile_error))(?: \(exit \d+\))?(?:; cleanup uncertain; preserving private workspace)?$/)?.[1];
  const scenarioSummary = orchestration.match(/^shared_pool_scenario:([a-z0-9-]+)(?: \(exit \d+\))?(?:; cleanup uncertain; preserving private workspace)?$/)?.[1];
  const scenario = scenarioSummary && requiredNames.includes(scenarioSummary) ? `scenario_${scenarioSummary}` : '';
  const stepMatch = orchestration.match(/^shared_pool_step:([a-z0-9_]+):(0|[1-9]\d{0,2})(?: \(exit \d+\))?(?:; cleanup uncertain; preserving private workspace)?$/);
  const stepStatus = stepMatch ? Number(stepMatch[2]) : NaN;
  const step = stepMatch && sharedPoolBuildPhases.includes(stepMatch[1]) && Number.isInteger(stepStatus) && stepStatus >= 0 && stepStatus <= 255 ?
    `step_${stepMatch[1]}_exit_${stepStatus}` : '';
  const detail = compileSummary || scenario || compile || step ||
    (/^timed out(?:;|$)/.test(orchestration) || statusLabel === 'timeout' ? 'timeout' : 'cause_unavailable');
  const summary = `G2 failure ${statusLabel}: ${detail}${uncertain ? `; ${cleanupUncertainMarker}` : ''}`;
  if (summary.length <= g2FailureSummaryMaxChars) return summary;
  return `G2 failure ${statusLabel}: cause_unavailable${uncertain ? `; ${cleanupUncertainMarker}` : ''}`;
}

function hasWrappedStepSummaryRecognition(source) {
  return source.includes('const stepMatch = orchestration.match(/^shared_pool_step:([a-z0-9_]+):(0|[1-9]\\d{0,2})(?: \\(exit \\d+\\))?(?:; cleanup uncertain; preserving private workspace)?$/);') &&
    source.includes('sharedPoolBuildPhases.includes(stepMatch[1])') &&
    source.includes('stepStatus <= 255');
}

function hasWrappedTypedSummaryRecognition(source) {
  const compileLine = source.split(/\r?\n/).find(line => line.includes('const compileSummary = orchestration.match('));
  const scenarioLine = source.split(/\r?\n/).find(line => line.includes('const scenarioSummary = orchestration.match('));
  return Boolean(compileLine && scenarioLine &&
    compileLine.includes('(?:; cleanup uncertain; preserving private workspace)?$/') &&
    scenarioLine.includes('(?:; cleanup uncertain; preserving private workspace)?$/') &&
    compileLine.includes('other_compile_error') && scenarioLine.includes('[a-z0-9-]+'));
}

function runExtractedInnerFailureFormatter(formatterSource, input) {
  const code = [
    'if (typeof process !== "undefined" || typeof require !== "undefined" || typeof fs !== "undefined" || typeof net !== "undefined" || typeof fetch !== "undefined" || typeof WebSocket !== "undefined") throw new Error("unexpected sandbox capability");',
    'const FAILURE_SUMMARY_MAX_CHARS = 240;',
    `const CLEANUP_UNCERTAIN_MARKER = ${JSON.stringify(cleanupUncertainMarker)};`,
    formatterSource,
    `formatFailureSummary(${JSON.stringify(input)});`,
  ].join('\n');
  return runInNewContext(code, Object.create(null), {
    timeout: 100,
    contextCodeGeneration: { strings: false, wasm: false },
  });
}

function runExtractedOuterFailureReducer(classifierSource, reducerSource, input) {
  const code = [
    'if (typeof process !== "undefined" || typeof require !== "undefined" || typeof fs !== "undefined" || typeof net !== "undefined" || typeof fetch !== "undefined" || typeof WebSocket !== "undefined") throw new Error("unexpected sandbox capability");',
    `const compilerSourceFiles = ${JSON.stringify(compilerSourceFiles)};`,
    `const requiredNames = ${JSON.stringify(requiredNames)};`,
    `const sharedPoolBuildPhases = ${JSON.stringify(sharedPoolBuildPhases)};`,
    `const cleanupUncertainMarker = ${JSON.stringify(cleanupUncertainMarker)};`,
    `const g2FailureSummaryMaxChars = ${g2FailureSummaryMaxChars};`,
    classifierSource,
    reducerSource,
    `summarizeCpuFailure(${JSON.stringify(input)});`,
  ].join('\n');
  return runInNewContext(code, Object.create(null), {
    timeout: 100,
    contextCodeGeneration: { strings: false, wasm: false },
  });
}

function verifyFailureDiagnosticControls() {
  const nested = [
    'Error: private fixed shared-pool CPU runner failed (exit 1)',
    'Error: fixture orchestration exit 1: compile_error tools/server/server-context.cpp:237 type_mismatch (exit 1)',
    '    at verifyCpu (C:\\private\\credential\\fixture.js:2:4)',
  ].join('\n');
  const compile = summarizeCpuFailure({ status: 1, stderr: nested });
  assert(compile === 'G2 failure exit_1: compile_error tools/server/server-context.cpp:237 type_mismatch',
    'nested compiler failure was not frontloaded as a bounded known-file diagnostic');
  const compilerOrchestrationCollision = summarizeCpuFailure({ status: 1, stderr: [
    'Error: fixture orchestration exit 1: RuntimeError: private wrapper failed /home/private/build',
    '/build/tools/server/server-context.cpp:238:9: error: no member named credential_token',
    'request=secret /home/private/build/source',
  ].join('\n') });
  assert(compilerOrchestrationCollision === 'G2 failure exit_1: compile_error tools/server/server-context.cpp:238 missing_member' &&
    !/private|credential_token|secret|\/build/.test(compilerOrchestrationCollision),
    'recognized compiler cause was suppressed by a generic orchestration failure');
  const scenario = summarizeCpuFailure({ status: 1, stderr: 'Error: fixture orchestration exit 1: shared_pool_scenario:busy-clear-rejected-unchanged (exit 1)\n/path/private/request-body' });
  assert(scenario === 'G2 failure exit_1: scenario_busy-clear-rejected-unchanged', 'recognized scenario failure was not mapped to its fixed ID');
  const transformed = transformedRunnerSource();
  assert(hasFailureDiagnosticTransform(transformed), 'transformed inner failure formatter is missing the finite phase parser');
  const missingInnerParser = transformed.replace('const stepFailure = (stderrValue, stdoutValue) => {', 'const removedStepFailure = (stderrValue, stdoutValue) => {');
  const unboundedInnerStatus = transformed.replace('status <= 255 ?', 'status <= 999 ?');
  const openInnerPhaseEnum = transformed.replace('stepPhases.includes(match[1])', 'true');
  const multipleInnerMarkersAccepted = transformed.replace('if (markers.length !== 1) return "";', 'if (markers.length < 1) return "";');
  const oldIndependentPerStreamHelper = [
    '  const stepFailure = (stderrValue, stdoutValue) => {',
    '    const markersIn = value => String(value).slice(-65536).split(/\\r?\\n/).filter(line => line.startsWith("SHARED_POOL_STEP_FAIL:"));',
    '    const stderrMarkers = markersIn(stderrValue);',
    '    const stdoutMarkers = markersIn(stdoutValue);',
    '    const markers = stderrMarkers.length === 1 ? stderrMarkers : stdoutMarkers.length === 1 ? stdoutMarkers : [];',
    '    if (markers.length !== 1) return "";',
    '    const match = markers[0].match(/^SHARED_POOL_STEP_FAIL:([a-z0-9_]+):(0|[1-9]\\d{0,2})$/);',
    '    if (!match) return "";',
    `    const stepPhases = ${JSON.stringify(sharedPoolBuildPhases)};`,
    '    const status = Number(match[2]);',
    "    return stepPhases.includes(match[1]) && Number.isInteger(status) && status >= 0 && status <= 255 ? 'shared_pool_step:' + match[1] + ':' + status : '';",
    '  };',
  ].join('\n');
  const combinedHelperStart = transformed.indexOf('  const stepFailure = (stderrValue, stdoutValue) => {');
  const combinedHelperEnd = transformed.indexOf('\n  };', combinedHelperStart) + '\n  };'.length;
  assert(combinedHelperStart >= 0 && combinedHelperEnd > combinedHelperStart, 'combined-stream helper boundary is missing');
  const independentPerStreamCountMutant = transformed.slice(0, combinedHelperStart) + oldIndependentPerStreamHelper + transformed.slice(combinedHelperEnd);
  assert(!hasFailureDiagnosticTransform(missingInnerParser) && !hasFailureDiagnosticTransform(unboundedInnerStatus) &&
    !hasFailureDiagnosticTransform(openInnerPhaseEnum) && !hasFailureDiagnosticTransform(multipleInnerMarkersAccepted) &&
    !hasFailureDiagnosticTransform(independentPerStreamCountMutant),
    'inner parser mutant was not rejected');
  const verifierSource = readFileSync(fileURLToPath(import.meta.url), 'utf8');
  const outerReducerStart = verifierSource.indexOf('function summarizeCpuFailure(');
  const outerReducerEnd = verifierSource.indexOf('\nfunction hasWrappedStepSummaryRecognition(', outerReducerStart);
  const outerReducerSource = outerReducerStart < 0 || outerReducerEnd < 0 ? '' : verifierSource.slice(outerReducerStart, outerReducerEnd);
  const classifierStart = verifierSource.indexOf('function classifyCompilerCause(');
  const classifierEnd = verifierSource.indexOf('\nfunction summarizeCpuFailure(', classifierStart);
  const classifierSource = classifierStart < 0 || classifierEnd < 0 ? '' : verifierSource.slice(classifierStart, classifierEnd);
  const outerRecognitionLine = outerReducerSource.split(/\r?\n/).find(line => line.includes('const stepMatch = orchestration.match('));
  const openOuterPhaseEnum = outerReducerSource.replace('sharedPoolBuildPhases.includes(stepMatch[1])', 'true');
  const unboundedOuterStatus = outerReducerSource.replace('stepStatus <= 255', 'stepStatus <= 999');
  assert(outerRecognitionLine && hasWrappedStepSummaryRecognition(outerReducerSource) &&
    !hasWrappedStepSummaryRecognition(outerReducerSource.replace(outerRecognitionLine, '')) &&
    !hasWrappedStepSummaryRecognition(openOuterPhaseEnum) && !hasWrappedStepSummaryRecognition(unboundedOuterStatus),
    'outer-recognition mutant was not rejected');
  assert(hasWrappedTypedSummaryRecognition(outerReducerSource), 'typed compiler/scenario cleanup-suffix recognition is missing');
  const compilerSummaryLine = outerReducerSource.split(/\r?\n/).find(line => line.includes('const compileSummary = orchestration.match('));
  const scenarioSummaryLine = outerReducerSource.split(/\r?\n/).find(line => line.includes('const scenarioSummary = orchestration.match('));
  assert(compilerSummaryLine && scenarioSummaryLine &&
    compilerSummaryLine.split('(?:; cleanup uncertain; preserving private workspace)?').length - 1 === 1 &&
    scenarioSummaryLine.split('(?:; cleanup uncertain; preserving private workspace)?').length - 1 === 1,
    'typed compiler/scenario cleanup suffix anchors changed');
  const compilerSuffixMutant = outerReducerSource.replace(compilerSummaryLine,
    compilerSummaryLine.replace('(?:; cleanup uncertain; preserving private workspace)?', ''));
  const scenarioSuffixMutant = outerReducerSource.replace(scenarioSummaryLine,
    scenarioSummaryLine.replace('(?:; cleanup uncertain; preserving private workspace)?', ''));
  assert(!hasWrappedTypedSummaryRecognition(compilerSuffixMutant) && !hasWrappedTypedSummaryRecognition(scenarioSuffixMutant),
    'typed-summary source predicate accepted an omitted cleanup-suffix recognizer');
  const compilerMutantStart = verifierSource.indexOf('function classifyCompilerCause(');
  const compilerMutantEnd = verifierSource.indexOf('\nfunction hasWrappedStepSummaryRecognition(', compilerMutantStart);
  const extractedClassifier = verifierSource.slice(compilerMutantStart, verifierSource.indexOf('\nfunction summarizeCpuFailure(', compilerMutantStart));
  const actualReducerStart = verifierSource.indexOf('function summarizeCpuFailure(');
  const actualReducerEnd = verifierSource.indexOf('\nfunction hasWrappedStepSummaryRecognition(', actualReducerStart);
  const actualReducer = verifierSource.slice(actualReducerStart, actualReducerEnd);
  assert(compilerMutantStart >= 0 && compilerMutantEnd > compilerMutantStart && extractedClassifier && actualReducer,
    'outer reducer/classifier extraction boundaries are missing');
  const formatterStart = transformed.indexOf('function formatFailureSummary(');
  const formatterEnd = transformed.indexOf('\nfunction failureOutcome(', formatterStart);
  assert(formatterStart >= 0 && formatterEnd > formatterStart, 'transformed inner failure formatter extraction boundary is missing');
  const formatterSource = transformed.slice(formatterStart, formatterEnd);
  assert(formatterSource.includes('const stepFailure = (stderrValue, stdoutValue) => {'), 'extracted formatter is not the transformed combined-stream phase-aware function');
  const typedRoundtrips = [
    {
      kind: 'compiler', uncertain: false,
      input: { status: 1, stderr: '[path]/tools/server/server-context.cpp:237:9: error: cannot convert from private type\n' },
      detail: 'compile_error tools/server/server-context.cpp:237 type_mismatch',
    },
    {
      kind: 'compiler', uncertain: true,
      input: { status: 1, stderr: `[path]/tools/server/server-context.cpp:237:9: error: cannot convert from private type\n${cleanupUncertainMarker} /private/cache` },
      detail: 'compile_error tools/server/server-context.cpp:237 type_mismatch',
    },
    {
      kind: 'scenario', uncertain: false,
      input: { status: 1, stdout: 'FAIL busy-clear-rejected-unchanged\n' },
      detail: 'shared_pool_scenario:busy-clear-rejected-unchanged',
    },
    {
      kind: 'scenario', uncertain: true,
      input: { status: 1, stdout: `FAIL busy-clear-rejected-unchanged\n${cleanupUncertainMarker} /private/cache` },
      detail: 'shared_pool_scenario:busy-clear-rejected-unchanged',
    },
  ];
  for (const item of typedRoundtrips) {
    const inner = runExtractedInnerFailureFormatter(formatterSource, item.input);
    const expectedInner = `${item.detail} (exit 1)${item.uncertain ? `; ${cleanupUncertainMarker}` : ''}`;
    assert(inner === expectedInner, `actual inner ${item.kind} formatter summary changed`);
    const wrapped = `Error: fixture orchestration exit 1: ${inner}`;
    const outerInput = { status: 1, stderr: wrapped };
    const outerDetail = item.kind === 'scenario' ? `scenario_${item.detail.slice('shared_pool_scenario:'.length)}` : item.detail;
    const expectedOuter = `G2 failure exit_1: ${outerDetail}${item.uncertain ? `; ${cleanupUncertainMarker}` : ''}`;
    const directOuter = summarizeCpuFailure(outerInput);
    const extractedOuter = runExtractedOuterFailureReducer(classifierSource, actualReducer, outerInput);
    assert(directOuter === expectedOuter && extractedOuter === expectedOuter,
      `actual inner-to-outer ${item.kind} roundtrip failed (cleanup=${item.uncertain}); inner=${inner}; outer=${directOuter}; extracted=${extractedOuter}`);
    const mutantReducer = item.kind === 'compiler' ? compilerSuffixMutant : scenarioSuffixMutant;
    const mutantResult = runExtractedOuterFailureReducer(classifierSource, mutantReducer, outerInput);
    const mutantExpected = item.uncertain ? `G2 failure exit_1: cause_unavailable; ${cleanupUncertainMarker}` : expectedOuter;
    assert(mutantResult === mutantExpected,
      `omitted ${item.kind} cleanup-suffix recognizer mutant was not rejected by the actual outer reducer: ${mutantResult}`);
    assert(inner.length <= g2FailureSummaryMaxChars && expectedOuter.length <= g2FailureSummaryMaxChars &&
      !/private type|private\/cache|FAIL |credential|requestBody/.test(`${inner}\n${expectedOuter}`),
      `typed ${item.kind} roundtrip exceeded privacy or summary bounds`);
  }
  const singleStdoutInner = runExtractedInnerFailureFormatter(formatterSource, {
    status: 1,
    stdout: 'SHARED_POOL_STEP_FAIL:apply_check:7',
  });
  const singleStdoutOuter = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${singleStdoutInner}` });
  assert(singleStdoutOuter === 'G2 failure exit_1: step_apply_check_exit_7', 'single stdout-only phase marker did not survive the real inner-to-outer roundtrip');
  for (const [label, stderrMarker, stdoutMarker] of [
    ['contradictory', 'SHARED_POOL_STEP_FAIL:base_builder:1', 'SHARED_POOL_STEP_FAIL:apply_check:2'],
    ['identical', 'SHARED_POOL_STEP_FAIL:cmake_rebuild:3', 'SHARED_POOL_STEP_FAIL:cmake_rebuild:3'],
  ]) {
    const inner = runExtractedInnerFailureFormatter(formatterSource, { status: 1, stderr: stderrMarker, stdout: stdoutMarker });
    const outer = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${inner}` });
    assert(outer === 'G2 failure exit_1: cause_unavailable' && inner.length <= g2FailureSummaryMaxChars && outer.length <= g2FailureSummaryMaxChars &&
      !/SHARED_POOL_STEP_FAIL|shared_pool_step:/.test(`${inner}\n${outer}`),
    `cross-stream ${label} markers were not rejected globally`);
  }
  const mutantFormatterStart = independentPerStreamCountMutant.indexOf('function formatFailureSummary(');
  const mutantFormatterEnd = independentPerStreamCountMutant.indexOf('\nfunction failureOutcome(', mutantFormatterStart);
  assert(mutantFormatterStart >= 0 && mutantFormatterEnd > mutantFormatterStart, 'per-stream mutant formatter extraction boundary is missing');
  const mutantInner = runExtractedInnerFailureFormatter(independentPerStreamCountMutant.slice(mutantFormatterStart, mutantFormatterEnd), {
    status: 1,
    stderr: 'SHARED_POOL_STEP_FAIL:base_builder:1',
    stdout: 'SHARED_POOL_STEP_FAIL:apply_check:2',
  });
  const mutantOuter = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${mutantInner}` });
  assert(mutantOuter === 'G2 failure exit_1: step_base_builder_exit_1', 'independent per-stream mutant did not reproduce the old cross-stream false classification');
  const hostile = summarizeCpuFailure({ status: 1, stderr: `[path]/src/llama-context.cpp:100001: error: token mismatch\ncredential=topsecret {"prompt":"sensitive"}\u202e\n${cleanupUncertainMarker} /home/secret` });
  assert(hostile === `G2 failure exit_1: cause_unavailable; ${cleanupUncertainMarker}` && !/topsecret|sensitive|secret|\u202e|100001/.test(hostile),
    'unknown/out-of-range compiler text or hostile payload escaped the bounded fallback');
  const realistic = summarizeCpuFailure({ status: 2, stderr: '[path]/src/llama-context.cpp:42:8: error: no member named private_symbol' });
  assert(realistic === 'G2 failure exit_2: compile_error src/llama-context.cpp:42 missing_member',
    'path-redacted compiler diagnostic positive control failed');
  const missingSymbol = classifyCompilerCause('/build/tools/server/server-queue.h:86:4: error: identifier was not declared in this scope');
  const genericCompile = classifyCompilerCause('/build/tools/server/server.cpp:19: error: vendor diagnostic with unrecognized wording');
  assert(missingSymbol === 'compile_error tools/server/server-queue.h:86 missing_symbol' &&
    genericCompile === 'compile_error tools/server/server.cpp:19 other_compile_error' &&
    compilerErrorClasses.includes(missingSymbol.split(' ').at(-1)) && compilerErrorClasses.includes(genericCompile.split(' ').at(-1)),
    'closed compiler category enum lacks missing-symbol or conservative fallback coverage');
  const clipped = summarizeCpuFailure({ status: 1, stdout: `${'noise\n'.repeat(12000)}\n/home/build/tools/server/server-queue.cpp:99999:3: error: expected \\';\\' before token` });
  assert(clipped === 'G2 failure exit_1: compile_error tools/server/server-queue.cpp:99999 syntax_error',
    'bounded tail compiler diagnostic control failed');
  const unknown = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: RuntimeError: raw diagnostic /private/path\n${cleanupUncertainMarker}` });
  assert(unknown === `G2 failure exit_1: cause_unavailable; ${cleanupUncertainMarker}`, 'unknown fallback lost cleanup uncertainty or exposed raw text');
  for (const phase of sharedPoolBuildPhases) {
    const innerSummary = runExtractedInnerFailureFormatter(formatterSource, {
      status: 1,
      stderr: `Error: fixture orchestration exit 1: RuntimeError: private detail /home/secret private_symbol credential=topsecret requestBody={"prompt":"sensitive"}\nSHARED_POOL_STEP_FAIL:${phase}:124\n${cleanupUncertainMarker} /private/build`,
    });
    const staged = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${innerSummary}` });
    assert(staged === `G2 failure exit_1: step_${phase}_exit_124; ${cleanupUncertainMarker}` &&
      innerSummary.length <= g2FailureSummaryMaxChars && staged.length <= g2FailureSummaryMaxChars &&
      !/private detail|private_symbol|topsecret|sensitive|SHARED_POOL_STEP_FAIL|\/home|\/private/.test(`${innerSummary}\n${staged}`),
      `fixed stage/status diagnostic failed for ${phase}`);
  }
  const zeroInnerSummary = runExtractedInnerFailureFormatter(formatterSource, { status: 1, stderr: 'SHARED_POOL_STEP_FAIL:base_builder:0' });
  const zeroStageStatus = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${zeroInnerSummary}` });
  assert(zeroStageStatus === 'G2 failure exit_1: step_base_builder_exit_0', 'safe zero-status phase marker was not classified');
  const maximumInnerSummary = runExtractedInnerFailureFormatter(formatterSource, { status: 1, stderr: 'SHARED_POOL_STEP_FAIL:provenance_write:255' });
  const maximumStageStatus = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${maximumInnerSummary}` });
  assert(maximumStageStatus === 'G2 failure exit_1: step_provenance_write_exit_255', 'safe maximum phase status was not classified');
  for (const invalidMarker of [
    'SHARED_POOL_STEP_FAIL:unlisted_stage:1',
    'SHARED_POOL_STEP_FAIL:cmake_rebuild:256',
    'SHARED_POOL_STEP_FAIL:cmake_rebuild:01',
    'SHARED_POOL_STEP_FAIL:cmake_rebuild:-1',
    'SHARED_POOL_STEP_FAIL:cmake_rebuild:9999',
    'SHARED_POOL_STEP_FAIL:source_union:1\nSHARED_POOL_STEP_FAIL:apply_check:2',
  ]) {
    const invalidInnerSummary = runExtractedInnerFailureFormatter(formatterSource, { status: 1, stderr: invalidMarker });
    const rejectedMarker = summarizeCpuFailure({ status: 1, stderr: `Error: fixture orchestration exit 1: ${invalidInnerSummary}` });
    assert(rejectedMarker === 'G2 failure exit_1: cause_unavailable' &&
      !/unlisted_stage|256|9999|SHARED_POOL_STEP_FAIL|cmake_rebuild/.test(`${invalidInnerSummary}\n${rejectedMarker}`),
      'unknown phase or unsafe phase status escaped fixed fallback');
  }
  const rawMarkerBypass = summarizeCpuFailure({ status: 1, stderr: 'SHARED_POOL_STEP_FAIL:source_union:124' });
  assert(rawMarkerBypass === 'G2 failure exit_1: cause_unavailable', 'outer reducer accepted a raw marker outside the typed inner wrapper');
  const timeoutInnerSummary = runExtractedInnerFailureFormatter(formatterSource, {
    status: null,
    error: { message: 'spawnSync timed out at /secret', code: 'ETIMEDOUT' },
    stderr: `SHARED_POOL_STEP_FAIL:apply_check:124\n${cleanupUncertainMarker} /secret`,
  });
  assert(timeoutInnerSummary.startsWith('timed out; shared_pool_step:apply_check:124') &&
    timeoutInnerSummary.includes(cleanupUncertainMarker) && !timeoutInnerSummary.includes('/secret'),
    'inner timeout formatter lost its finite phase or cleanup summary');
  const timedOut = summarizeCpuFailure({
    status: null,
    error: Object.assign(new Error('timed out at /secret'), { code: 'ETIMEDOUT' }),
    stderr: `Error: fixture orchestration timeout: ${timeoutInnerSummary}`,
  });
  assert(timedOut === `G2 failure timeout: timeout; ${cleanupUncertainMarker}`, 'timeout and uncertain-cleanup status were not preserved');
  assert([compile, compilerOrchestrationCollision, scenario, hostile, realistic, clipped, unknown, timedOut, zeroStageStatus, maximumStageStatus].every(value => value.length <= g2FailureSummaryMaxChars),
    'failure summary exceeded its fixed character bound');
}

function validateTranscript(transcript, expected) {
  const lines = transcript.trimEnd().split(/\r?\n/);
  const want = expected.flatMap(name => [`RUN: ${name}`, `PASS: ${name}`]);
  assert(lines.length === want.length && lines.every((line, index) => line === want[index]), 'CPU transcript differs from exact ordered RUN/PASS inventory');
}

function verifyFrozenPins(readPinned = read) {
  for (const [rel, bytes, digest] of frozen) {
    const data = readPinned(rel);
    assert(data.length === bytes && sha256(data) === digest, `leaf20 frozen helper changed: ${rel}`);
  }
}

function validateScenarioInventory(names) {
  assert(names.length === 13 && JSON.stringify(names) === JSON.stringify(expectedScenarioInventory) &&
    new Set(names).size === names.length, 'exact required scenario inventory changed or contains duplicates');
}

function parsePatch(text) {
  assert(text.startsWith('From 58f4f01b71ac68f0d1db8d73a18c2dfd8e3f091a '), 'patch identity header missing');
  assert(text.includes('Pinned base: ggml-org/llama.cpp 62acc89c26c66076cb72e049f307fbe93b8b9750'), 'exact upstream base pin missing');
  const names = [...text.matchAll(/^diff --git a\/([^\r\n ]+) b\/([^\r\n ]+)$/gm)];
  assert(names.length > 0, 'patch contains no git diff sections');
  const observed = names.map(([, a, b]) => { assert(a === b, 'rename or copy diff is forbidden'); return a; });
  const unique = new Set(observed);
  assert(observed.length === unique.size, 'each allowed upstream path must have exactly one diff section');
  assert(unique.size === allowed.size && [...unique].every(name => allowed.has(name)), 'patch paths differ from exact eight-file allowlist');
  assert(text.includes('+++ b/'), 'patch has no insertions');
  const lines = text.split(/\r?\n/);
  let hunk = null;
  let hunkCount = 0;
  let lastOldStart = 0;
  for (const line of lines) {
    if (line.startsWith('diff --git ')) lastOldStart = 0;
    const header = line.match(/^@@ -(\d+),(\d+) \+(\d+),(\d+) @@/);
    if (header) {
      if (hunk) assert(hunk.old === hunk.expectedOld && hunk.new === hunk.expectedNew && hunk.new > hunk.old, 'prior patch hunk count or insertion-only check failed');
      const oldStart = Number(header[1]);
      assert(oldStart >= lastOldStart, 'patch hunks must be sorted by original source line');
      lastOldStart = oldStart;
      hunk = { expectedOld: Number(header[2]), expectedNew: Number(header[4]), old: 0, new: 0 };
      hunkCount++;
      continue;
    }
    if (!hunk) continue;
    if (line.startsWith('+')) hunk.new++;
    else if (line.startsWith('-')) throw new Error('patch contains a replacement or removal');
    else if (line.startsWith(' ')) { hunk.old++; hunk.new++; }
    else if (line.startsWith('diff --git ')) {
      assert(hunk.old === hunk.expectedOld && hunk.new === hunk.expectedNew && hunk.new > hunk.old, 'patch hunk count or insertion-only check failed');
      hunk = null;
    }
  }
  if (hunk) assert(hunk.old === hunk.expectedOld && hunk.new === hunk.expectedNew && hunk.new > hunk.old, 'final patch hunk count or insertion-only check failed');
  assert(hunkCount >= 10, 'patch omits required insertion hunks');
  return [...unique];
}

function sharedPoolClearParserIsSafe(patch) {
  const start = patch.indexOf('+    this->post_shared_pool_clear =');
  const end = patch.indexOf('     this->get_props =', start);
  if (start < 0 || end <= start) return false;
  const route = patch.slice(start, end);
  const ordered = [
    'req.body.size() > 512',
    'json::parse_no_throw(req.body)',
    'body.size() != 3',
    '!body["slot"].is_number_integer()',
    '!body["incarnation"].is_string()',
    '!body["epoch"].is_string()',
    'const std::string slot_text = body["slot"].dump();',
    "slot_text[0] == '-'",
    'for (const char digit_char : slot_text)',
    "digit_char < '0' || digit_char > '9'",
    'requested_slot > (63U - digit) / 10U',
    'requested_slot = requested_slot * 10U + digit;',
    'requested_slot >= 64',
    'server_task task(SERVER_TASK_TYPE_SHARED_POOL_CLEAR)',
  ];
  let previous = -1;
  for (const token of ordered) {
    const at = route.indexOf(token);
    if (at <= previous) return false;
    previous = at;
  }
  return !route.includes('json::parse(req.body, nullptr, false)') &&
    !route.includes('is_number_unsigned()') &&
    !route.includes('get<int64_t>()') &&
    !route.includes('get<uint64_t>()');
}

function sharedPoolRouteGuardsAreSafe(patch) {
  const start = patch.indexOf('+    this->get_shared_pool =');
  const end = patch.indexOf('\n     this->get_props =', start);
  if (start < 0 || end <= start) return false;
  const routes = patch.slice(start, end);
  const getStart = routes.indexOf('+    this->get_shared_pool =');
  const clearStart = routes.indexOf('+    this->post_shared_pool_clear =');
  if (getStart < 0 || clearStart <= getStart) return false;
  const routeTexts = [routes.slice(getStart, clearStart), routes.slice(clearStart)];
  const expected = '+        if (!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()) { res->status = 404;';
  return routeTexts.every(route => {
    const guard = route.indexOf(expected);
    const admission = route.indexOf('admit_shared_pool_request()');
    const effect = Math.min(...['SERVER_TASK_TYPE_SHARED_POOL_GET', 'SERVER_TASK_TYPE_SHARED_POOL_CLEAR', 'post_if_awake'].map(token => {
      const at = route.indexOf(token);
      return at < 0 ? Number.POSITIVE_INFINITY : at;
    }));
    return guard >= 0 && route.indexOf(expected, guard + expected.length) < 0 &&
      !route.includes('ctx_server.checkpoint_compat_enabled()') && !route.includes('ctx_server.shared_pool_enabled()') &&
      admission > guard && effect > guard && route.indexOf('shared pool opt-in is disabled', guard) > guard;
  });
}

function sourceArtifactOracle(patch, descriptorPatch, verifier, builder) {
  const checks = [
    ['plain unified only', /kv_unified|unified/i.test(patch) && /llama_kv_cache/.test(patch)],
    ['exact plain LLAMA architecture and sequence geometry', /LLM_ARCH_LLAMA/.test(patch) && /n_seq_max/.test(patch)],
    ['actual physical used count', /get_used\(\)/.test(patch)],
    ['per-sequence membership', /seq_has\(/.test(patch)],
    ['free derived from total minus physical used', /\{"freeCells", total - used\}/.test(patch)],
    ['unattributed physical cells', /unattributedCells/.test(patch)],
    ['queued snapshot and clear task types', /SERVER_TASK_TYPE_SHARED_POOL_GET/.test(patch) && /SERVER_TASK_TYPE_SHARED_POOL_CLEAR/.test(patch)],
    ['decode-yield allowlist stays metrics and slot-get only', /^\s*if \(is_yielding && task\.type != SERVER_TASK_TYPE_METRICS && task\.type != SERVER_TASK_TYPE_SLOT_GET\) \{$/m.test(patch)],
    ['shared-pool cases precede the unchanged completion label group', /switch \(task\.type\) \{\n\+            case SERVER_TASK_TYPE_SHARED_POOL_GET:[\s\S]*\+            case SERVER_TASK_TYPE_SHARED_POOL_CLEAR:[\s\S]*\n             case SERVER_TASK_TYPE_COMPLETION:\n             case SERVER_TASK_TYPE_INFILL:\n             case SERVER_TASK_TYPE_EMBEDDING:\n             case SERVER_TASK_TYPE_RERANK:/.test(patch)],
    ['backend synchronization before observation', /synchronize\(\)/.test(patch)],
    ['main/deferred/unhandled queue atomic empty fence and safe awake post', /with_empty_task_queues/.test(patch) && /!queue_tasks\.empty\(\)/.test(patch) && /!queue_tasks_deferred\.empty\(\)/.test(patch) && /!queue_tasks_unhandled\.empty\(\)/.test(patch) && /worker\.busy \|\| worker\.yielding/.test(patch) && /post_if_awake/.test(patch) && /remove_waiting_task_id\(task_id\)/.test(patch)],
    ['ambiguous occupied cells and noncanonical slot ids fail closed', /unattributed != 0/.test(patch) && /slot\.id != static_cast<int>\(i\)/.test(patch) && /canonical_slots/.test(patch)],
    ['exact sequence removal and post-clear recount', /prompt_clear\(\)/.test(patch) && /\{"membershipCells", members\[i\]\}/.test(patch) && /\{"membershipCells", 0\}/.test(patch)],
    ['separate default-off startup opt-in', /LLAMA_CHECKPOINT_COMPAT_SHARED_POOL/.test(patch) && /strcmp\([^\n]*"1"/.test(patch)],
    ['pool-off preserves descriptor-only behavior and optional nonce failure is closed', /shared_pool_state_enabled_for_process/.test(patch) && /if \(!shared_pool_state_enabled_for_process\(\)\) return true/.test(patch) && /if \(!shared_pool_state_enabled_for_process\(\)\) return;/.test(patch) && /catch \(\.\.\.\)[\s\S]{0,180}shared_pool_epoch_overflow = true/.test(patch)],
    ['existing descriptor opt-in prerequisite', /checkpoint_compat_enabled/.test(patch)],
    ['legacy descriptor route is fenced from HTTP-thread reads in shared-pool mode', /if \(ctx_server\.shared_pool_enabled\(\)\) \{[\s\S]{0,300}descriptor route is unavailable in shared-pool mode[\s\S]{0,120}get_checkpoint_compat_descriptor/.test(patch)],
    ['versioned bounded canonical response', /schemaVersion/.test(patch) && /canonical|\.dump\(\)/.test(patch)],
    ['pool incarnation and decimal epoch fencing', /\{"incarnation", shared_pool_incarnation\}/.test(patch) && /\{"epoch", std::to_string\(shared_pool_epoch\)\}/.test(patch)],
    ['stale, active, queued and overflow refusals', /request\.epoch != std::to_string\(shared_pool_epoch\)/.test(patch) && /stale/.test(patch) && /is_processing\(\)/.test(patch) && /overflow/.test(patch)],
    ['active slot release headroom is reserved before selection and increments', /shared_pool_can_advance_epoch\(2\)[\s\S]{0,300}get_available_slot\(task\)/.test(patch) && /shared_pool_advance_epoch\(true\)/.test(patch) && /active <= max_epoch - extra/.test(patch)],
    ['bounded slots and cells before allocation or scan', /max_slots = 64/.test(patch) && /max_sequences = 64/.test(patch) && /max_cells = 65536/.test(patch)],
    ['bounded expensive observation admission and exact-clear payload', /shared_pool_requests\{0\}/.test(patch) && /current < 4\)/.test(patch) && /req\.body\.size\(\) > 512/.test(patch) && /requested_slot >= 64/.test(patch)],
    ['common_json wrapper-safe exact-clear parser with overflow-safe slot bounds', sharedPoolClearParserIsSafe(patch)],
    ['GET and CLEAR use both implementation-context opt-ins before admission or task effects', sharedPoolRouteGuardsAreSafe(patch)],
    ['no idle-slot cache clearing or HTTP slot walk', /SERVER_TASK_TYPE_SHARED_POOL_CLEAR/.test(patch) && !/for\s*\([^)]*slots[^)]*\).*req/.test(patch)],
    ['descriptor startup is also bound', /LLAMA_CHECKPOINT_COMPAT_DESCRIPTOR/.test(descriptorPatch)],
    ['fixed CPU builder is bounded and pinned', /PINNED_COMMIT=62acc89c26c66076cb72e049f307fbe93b8b9750/.test(builder) && /timeout --signal=TERM --kill-after/.test(builder)],
    ['original fixture cleanup controls exist', /parent_pidfd/.test(verifier) && /cleanup uncertain; preserving private workspace/.test(verifier) && /namespace-child-reaped/.test(verifier)],
  ];
  for (const [label, ok] of checks) assert(ok, `source control failed: ${label}`);
  const clearStart = patch.indexOf('case SERVER_TASK_TYPE_SHARED_POOL_CLEAR:');
  const clearText = patch.slice(clearStart);
  const clearBefore = clearText.indexOf('request.epoch != std::to_string(shared_pool_epoch)');
  const clearFence = clearText.indexOf('with_empty_task_queues');
  const clearSupport = clearText.indexOf('llama_shared_pool_get_counts(ctx_tgt, before.size()');
  const clearRemove = clearText.indexOf('slot.prompt_clear();');
  const clearReset = clearText.indexOf('slot.reset();');
  const clearSync = clearText.indexOf('llama_synchronize(ctx_tgt);');
  const clearRecount = clearText.indexOf('llama_shared_pool_get_counts(ctx_tgt, after.size()');
  const clearReceipt = clearText.indexOf('result->data = {{"schemaVersion", 1}, {"cleared", true}');
  assert(clearStart >= 0 && clearBefore >= 0 && clearSupport > clearBefore && clearFence > clearSupport && clearRemove > clearFence && clearReset > clearRemove && clearSync > clearReset && clearRecount > clearSync && clearReceipt > clearRecount,
    'clear preconditions, support/bounds proof, empty-queue mutation fence, sequence/metadata removal, synchronization, recount, and receipt order changed');
  assert((patch.match(/^\+.*auto res = create_response\(true\);$/gm) || []).length === 2 && /post_if_awake/.test(patch) && /!running \|\| sleeping/.test(patch),
    'shared-pool HTTP routes must not auto-wake a sleeping server');
  assert(clearText.indexOf('after[request.id_slot] != 0') > clearRecount, 'clear receipt no longer verifies the exact target sequence');
  const taskSwitch = patch.indexOf('switch (task.type) {');
  const sharedGet = patch.indexOf('+            case SERVER_TASK_TYPE_SHARED_POOL_GET:', taskSwitch);
  const sharedClear = patch.indexOf('+            case SERVER_TASK_TYPE_SHARED_POOL_CLEAR:', sharedGet);
  const originalCompletion = patch.indexOf('             case SERVER_TASK_TYPE_COMPLETION:', sharedClear);
  assert(taskSwitch >= 0 && sharedGet > taskSwitch && sharedClear > sharedGet && originalCompletion > sharedClear &&
    patch.indexOf('             case SERVER_TASK_TYPE_INFILL:', originalCompletion) > originalCompletion &&
    patch.indexOf('             case SERVER_TASK_TYPE_EMBEDDING:', originalCompletion) > originalCompletion &&
    patch.indexOf('             case SERVER_TASK_TYPE_RERANK:', originalCompletion) > originalCompletion,
    'shared-pool GET/CLEAR must be independent switch cases before the original completion label group');
  return checks.length;
}

function invalidClearScenarioIsBounded(runner) {
  const start = runner.indexOf('        def wrong_slot_epoch():');
  const end = runner.indexOf("        run_case('wrong-slot-epoch-rejected-unchanged', wrong_slot_epoch)", start);
  if (start < 0 || end <= start) return false;
  const scenario = runner.slice(start, end);
  const required = [
    'before = snapshot(p)',
    'clear_payload(-1)',
    'clear_payload(64)',
    'clear_payload(18446744073709551615)',
    'clear_payload(18446744073709551616)',
    'clear_payload(0.5)',
    "clear_payload('0')",
    'dict(clear_payload(0), extra=True)',
    '"slot":',
    "' ' * 513",
    "status != 400",
    "(after['epoch'], after['pool'], after['slots']) != (before['epoch'], before['pool'], before['slots'])",
  ];
  return required.every(token => scenario.includes(token)) &&
    runner.includes('body.encode() if isinstance(body, str)') &&
    (runner.match(/run_case\('wrong-slot-epoch-rejected-unchanged', wrong_slot_epoch\)/g) || []).length === 1;
}

function lifecycleRoutesAreSafe(runner) {
  const start = runner.indexOf('        def lifecycle():');
  const end = runner.indexOf("        run_case('load-restore-erase-clear-epoch-fence', lifecycle)", start);
  if (start < 0 || end <= start) return false;
  const scenario = runner.slice(start, end);
  const saveCall = "status, _ = request(p, 'POST', '/slots/0?action=save', {'filename':'slot.bin'})";
  const saveCheck = "if status != 200: raise RuntimeError('fixed slot save failed')";
  const restoreCall = "status, _ = request(p, 'POST', '/slots/0?action=restore', {'filename':'slot.bin'})";
  const restoreEpochCheck = "if status != 200 or int(restored['epoch']) <= int(before['epoch']): raise RuntimeError('restore did not fence epoch')";
  const eraseCall = "status, _ = request(p, 'POST', '/slots/0?action=erase', {})";
  const eraseEpochCheck = "if status != 200 or int(erased['epoch']) <= int(restored['epoch']): raise RuntimeError('erase did not fence epoch')";
  const required = [
    'p = state[\'p\']; completion(p, 0, 32, 2); before = snapshot(p)',
    saveCall, saveCheck, restoreCall,
    "restored = snapshot(p)", restoreEpochCheck,
    eraseCall, "erased = snapshot(p)", eraseEpochCheck,
  ];
  let prior = -1;
  for (const text of required) {
    if (scenario.split(text).length - 1 !== 1) return false;
    const at = scenario.indexOf(text);
    if (at <= prior) return false;
    prior = at;
  }
  const postRequests = scenario.match(/request\(p, 'POST', '[^']+'/g) || [];
  return postRequests.length === 3 &&
    (runner.match(/run_case\('load-restore-erase-clear-epoch-fence', lifecycle\)/g) || []).length === 1;
}

function mutateWrongSlotScenario(runner, from, to) {
  const start = runner.indexOf('        def wrong_slot_epoch():');
  const end = runner.indexOf("        run_case('wrong-slot-epoch-rejected-unchanged', wrong_slot_epoch)", start);
  if (start < 0 || end <= start) return runner;
  const scenario = runner.slice(start, end);
  if (!scenario.includes(from)) return runner;
  return runner.slice(0, start) + scenario.replace(from, to) + runner.slice(end);
}

function sourceOracle(patch, descriptorPatch, verifier, builder) {
  const checks = sourceArtifactOracle(patch, descriptorPatch, verifier, builder);
  validateScenarioInventory(requiredNames);
  const runPass = requiredNames.flatMap(name => [`RUN: ${name}`, `PASS: ${name}`]).join('\n');
  validateTranscript(runPass, requiredNames);
  for (const mutant of [
    runPass.split('\n').slice(0, -2).join('\n'),
    runPass.replace(`RUN: ${requiredNames[1]}\nPASS: ${requiredNames[1]}`, `RUN: ${requiredNames[0]}\nPASS: ${requiredNames[0]}\nRUN: ${requiredNames[1]}\nPASS: ${requiredNames[1]}`),
    runPass.replace(`RUN: ${requiredNames[1]}\nPASS: ${requiredNames[1]}`, `RUN: ${requiredNames[2]}\nPASS: ${requiredNames[2]}`),
  ]) {
    let rejected = false;
    try { validateTranscript(mutant, requiredNames); } catch { rejected = true; }
    assert(rejected, 'missing, duplicate, or skipped transcript mutant was accepted');
  }
  const mutants = [
    [patch.replaceAll('LLAMA_CHECKPOINT_COMPAT_SHARED_POOL', 'LLAMA_CHECKPOINT_COMPAT_POOL_MUTANT'), 'separate default-off startup opt-in'],
    [patch.replace('get_used()', 'get_used_mutant()'), 'actual physical used count'],
    [patch.replace('seq_has(', 'seq_has_mutant('), 'per-sequence membership'],
    [patch.replaceAll('incarnation', 'incarnation_mutant'), 'pool incarnation and decimal epoch fencing'],
    [patch.replaceAll('membershipCells', 'membershipCells_mutant'), 'exact sequence removal and post-clear recount'],
    [patch.replace('ctx->synchronize();', 'ctx->synchronize_mutant();'), 'backend synchronization before observation'],
    [patch.replaceAll('{"freeCells", total - used}', '{"freeCells", total}'), 'free derived from total minus physical used'],
    [patch.replace('if (is_yielding && task.type != SERVER_TASK_TYPE_METRICS && task.type != SERVER_TASK_TYPE_SLOT_GET) {', 'if (is_yielding && task.type != SERVER_TASK_TYPE_METRICS && task.type != SERVER_TASK_TYPE_SLOT_GET && task.type != SERVER_TASK_TYPE_SHARED_POOL_GET) {'), 'decode-yield allowlist stays metrics and slot-get only'],
    [patch.replace('+                    slot.prompt_clear();\n+                    slot.reset();', '+                    slot.reset();\n+                    slot.prompt_clear();'), 'clear preconditions, support/bounds proof, empty-queue mutation fence, sequence/metadata removal, synchronization, recount, and receipt order changed'],
    [patch.replace('request.epoch != std::to_string(shared_pool_epoch)', 'false'), 'stale, active, queued and overflow refusals'],
    [patch.replace('shared_pool_can_advance_epoch(2)', 'true'), 'active slot release headroom is reserved before selection and increments'],
    [patch.replace('after[request.id_slot] != 0', 'after[0] != 0'), 'clear receipt no longer verifies the exact target sequence'],
    [patch.replace('!queue_tasks_unhandled.empty()', 'queue_tasks_unhandled.empty()'), 'main/deferred/unhandled queue atomic empty fence and safe awake post'],
    [patch.replaceAll('!running || sleeping', 'false'), 'shared-pool HTTP routes must not auto-wake a sleeping server'],
    [patch.replace('         switch (task.type) {\n+            case SERVER_TASK_TYPE_SHARED_POOL_GET:', '         switch (task.type) {\n             case SERVER_TASK_TYPE_COMPLETION:\n+            case SERVER_TASK_TYPE_SHARED_POOL_GET:'), 'shared-pool cases precede the unchanged completion label group'],
    [patch.replaceAll('unattributed != 0', 'unattributed == 0'), 'ambiguous occupied cells and noncanonical slot ids fail closed'],
    [patch.replace('slot.id != static_cast<int>(i)', 'slot.id < 0'), 'ambiguous occupied cells and noncanonical slot ids fail closed'],
    [patch.replace('if (ctx_server.shared_pool_enabled()) {', 'if (false) {'), 'legacy descriptor route is fenced from HTTP-thread reads in shared-pool mode'],
    [patch.replace('current < 4)', 'current < 400)'), 'bounded expensive observation admission and exact-clear payload'],
    [patch.replace('json::parse_no_throw(req.body)', 'json::parse(req.body, nullptr, false)'), 'common_json wrapper-safe exact-clear parser with overflow-safe slot bounds'],
    [patch.replace('!body["slot"].is_number_integer()', 'body["slot"].is_number_integer()'), 'common_json wrapper-safe exact-clear parser with overflow-safe slot bounds'],
    [patch.replace("slot_text[0] == '-'", "slot_text[0] != '-'") , 'common_json wrapper-safe exact-clear parser with overflow-safe slot bounds'],
    [patch.replace('requested_slot > (63U - digit) / 10U', 'false'), 'common_json wrapper-safe exact-clear parser with overflow-safe slot bounds'],
    [patch.replace('requested_slot >= 64', 'requested_slot > 64'), 'bounded expensive observation admission and exact-clear payload'],
    [patch.replace('req.body.size() > 512', 'req.body.size() > 513'), 'bounded expensive observation admission and exact-clear payload'],
    [patch.replace('body.size() != 3', 'body.size() != 2'), 'common_json wrapper-safe exact-clear parser with overflow-safe slot bounds'],
    [patch.replaceAll('!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()', '!checkpoint_compat_enabled_for_process()'), 'GET and CLEAR use both implementation-context opt-ins before admission or task effects'],
    [patch.replaceAll('!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()', '!server_context_impl::shared_pool_enabled_for_process()'), 'GET and CLEAR use both implementation-context opt-ins before admission or task effects'],
    [patch.replaceAll('!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()', '!ctx_server.checkpoint_compat_enabled() || !ctx_server.shared_pool_enabled()'), 'GET and CLEAR use both implementation-context opt-ins before admission or task effects'],
    [patch.replace('+        if (!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()) { res->status = 404; res->data = "{\\"error\\":\\"shared pool opt-in is disabled\\"}"; return res; }\n+        if (!admit_shared_pool_request())', '+        if (!admit_shared_pool_request())\n+        if (!checkpoint_compat_enabled_for_process() || !server_context_impl::shared_pool_enabled_for_process()) { res->status = 404; res->data = "{\\"error\\":\\"shared pool opt-in is disabled\\"}"; return res; }'), 'GET and CLEAR use both implementation-context opt-ins before admission or task effects'],
  ];
  for (const [mutant, expectedFailure] of mutants) {
    assert(mutant !== patch, `source mutation did not change artifact: ${expectedFailure}`);
    let rejection = '';
    try { sourceArtifactOracle(mutant, descriptorPatch, verifier, builder); }
    catch (error) { rejection = String(error?.message || error); }
    assert(rejection.includes(expectedFailure), `actual source oracle accepted or misclassified mutant (${expectedFailure}): ${rejection || 'no rejection'}`);
  }
  let inventoryRejected = false;
  try { validateScenarioInventory([...requiredNames, requiredNames[0]]); }
  catch (error) { inventoryRejected = String(error?.message || error).includes('exact required scenario inventory'); }
  assert(inventoryRejected, 'actual scenario inventory validator accepted a duplicate scenario');
  return { checks, tests: requiredNames.length };
}

function verifySource() {
  verifyFrozenPins();
  verifyFailureDiagnosticControls();
  let pinRejected = false;
  try {
    const changedPin = frozen[0][0];
    verifyFrozenPins(rel => {
      const data = read(rel);
      return rel === changedPin ? Buffer.concat([data, Buffer.from([0])]) : data;
    });
  } catch (error) { pinRejected = String(error?.message || error).includes('leaf20 frozen helper changed'); }
  assert(pinRejected, 'actual frozen-helper pin validator accepted a byte mutation');
  const patch = readFileSync(patchPath, 'utf8');
  const descriptorPatch = readFileSync(basePatchPath, 'utf8');
  const verifier = read('scripts/checkpoint-compat/verify-cpu-descriptor.mjs').toString('utf8');
  const builder = read('scripts/checkpoint-compat/build-cpu-fixture.sh').toString('utf8');
  const paths = parsePatch(patch);
  const summary = sourceOracle(patch, descriptorPatch, verifier, builder);
  const runner = transformedRunnerSource();
  assert(lifecycleRoutesAreSafe(runner), 'fixed slot lifecycle routes, bodies, status checks, or epoch order changed');
  const saveRoute = "'/slots/0?action=save'";
  const restoreRoute = "'/slots/0?action=restore'";
  const saveLine = "status, _ = request(p, 'POST', '/slots/0?action=save', {'filename':'slot.bin'})";
  const restoreLine = "status, _ = request(p, 'POST', '/slots/0?action=restore', {'filename':'slot.bin'})";
  const routeMutants = [
    [replaceExactlyOnce(runner, saveRoute, "'/slots'", 'bare lifecycle path'), 'old bare /slots route'],
    [replaceExactlyOnce(runner, saveRoute, "'/slots?action=save&id_slot=0'", 'query-only lifecycle slot'), 'query-only slot id'],
    [replaceExactlyOnce(runner, saveRoute, "'/slots/1?action=save'", 'wrong lifecycle path slot'), 'wrong path slot id'],
    [replaceExactlyOnce(runner, saveRoute, "'/slots/0'", 'missing lifecycle action'), 'missing action'],
    [runner.replace(saveLine, 'LIFECYCLE_ROUTE_ORDER_SENTINEL').replace(restoreLine, saveLine).replace('LIFECYCLE_ROUTE_ORDER_SENTINEL', restoreLine), 'save/restore route order'],
  ];
  for (const [mutant, label] of routeMutants) {
    assert(mutant !== runner && !lifecycleRoutesAreSafe(mutant), `lifecycle route mutant was accepted: ${label}`);
  }
  assert(invalidClearScenarioIsBounded(runner), 'invalid exact-clear payload controls are missing or escaped the existing wrong-slot scenario');
  for (const [mutant, label] of [
    [mutateWrongSlotScenario(runner, 'clear_payload(-1)', 'clear_payload(0)'), 'negative-slot rejection'],
    [mutateWrongSlotScenario(runner, 'clear_payload(18446744073709551615)', 'clear_payload(63)'), 'maximum unsigned-slot rejection'],
    [mutateWrongSlotScenario(runner, 'clear_payload(0.5)', 'clear_payload(0)'), 'noninteger-slot rejection'],
    [mutateWrongSlotScenario(runner, 'dict(clear_payload(0), extra=True)', 'clear_payload(0)'), 'exact-key rejection'],
    [mutateWrongSlotScenario(runner, "'{\"slot\":'", 'clear_payload(0)'), 'malformed-JSON rejection'],
    [mutateWrongSlotScenario(runner, "' ' * 513", "' ' * 512"), '512-byte body bound'],
    [mutateWrongSlotScenario(runner, 'status != 400', 'status < 400'), '400-before-enqueue assertion'],
    [mutateWrongSlotScenario(runner, "(after['epoch'], after['pool'], after['slots']) != (before['epoch'], before['pool'], before['slots'])", 'False'), 'invalid-request state preservation'],
    [runner.replace('body.encode() if isinstance(body, str) else ', ''), 'raw malformed/oversized request transport'],
  ]) {
    assert(!invalidClearScenarioIsBounded(mutant), `invalid-clear source mutant passed: ${label}`);
  }
  const runnerSyntax = spawnSync(process.execPath, ['--input-type=module', '--check'], {
    input: runner, encoding: 'utf8', maxBuffer: 1024 * 1024, windowsHide: true,
  });
  assert(!runnerSyntax.error && runnerSyntax.status === 0, `transformed frozen-supervisor runner syntax failed: ${runnerSyntax.stderr || runnerSyntax.error?.message || runnerSyntax.status}\n${runner.split(/\r?\n/).slice(1286, 1296).join('\n')}`);
  console.log(`source controls: ${summary.checks + 1}; required scenario inventory: ${summary.tests}; patch paths: ${paths.length}`);
  console.log('fixed slot lifecycle route positive and five route mutants passed');
  console.log('frozen CPU supervisor transformation syntax passed');
  console.log('initialized shared pool source controls passed');
}

function replaceExactlyOnce(source, before, after, label) {
  assert(source.split(before).length - 1 === 1, `frozen runner transformation anchor changed: ${label}`);
  return source.replace(before, after);
}

function assertSharedPoolCleanupSupervisor(source) {
  const cleanupGuard = "if mode in ('controls', 'shared-pool'):\n    sentinel_parent_pid = os.getpid()";
  assert(source.split(cleanupGuard).length - 1 === 1, 'shared-pool mode does not reach the inherited timeout/parent-death cleanup controls');
  assert(source.includes("print('CHECKPOINT_CLEANUP_TIMEOUT_CONTROL_PASS', flush=True)") &&
    source.includes("print('CHECKPOINT_PARENT_DEATH_CONTROL_PASS', flush=True)"),
    'shared-pool cleanup supervisor guard lost timeout/parent-death marker bodies');
}

function assertSharedPoolInitializationOrder(source) {
  const patchDeclaration = "const sharedPoolPatchWsl = wslPath(path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0002-initialized-shared-pool.patch'));";
  assert(source.split(patchDeclaration).length - 1 === 1, 'shared-pool patch path declaration must occur exactly once');
  const declaration = source.indexOf(patchDeclaration);
  const limit = source.indexOf('const limit = 1024 * 1024;');
  const call = source.indexOf('function call(args, input) {');
  const uidGuard = source.indexOf("if (uid !== '1000') throw new Error(`WSL fixture UID mismatch: ${uid}`);");
  const generatorPath = source.indexOf('const generatorWsl = wslPath(generator);');
  const patchPath = source.indexOf("const patchWsl = wslPath(patch);");
  assert(limit >= 0 && call > limit && patchPath > uidGuard && uidGuard > call && generatorPath > patchPath && declaration > generatorPath,
    'shared-pool patch path must initialize after maxBuffer, fixed UID, and bounded WSL path preflight');
  assert(source.includes('const CPU_PREFLIGHT_BUDGET_MS = 30_000;') && source.includes('const CPU_PREFLIGHT_CALL_TIMEOUT_MS = 10_000;') &&
    source.includes('const CPU_MAIN_MIN_REMAINING_MS = 900_000;'), 'fixed preflight budgets changed during path initialization transform');
}

function hasFailureDiagnosticTransform(source) {
  const phaseOrder = [
    source.indexOf('run_shared_pool_step base_builder bash'),
    source.indexOf('run_shared_pool_step apply_check timeout'),
    source.indexOf('run_shared_pool_step apply_0002 timeout'),
    source.indexOf(sourceUnionFailureGuard),
    source.indexOf('if [[ "$actual_union" == "$expected_union" ]]'),
    source.indexOf('run_shared_pool_step cmake_rebuild timeout'),
    source.indexOf('run_shared_pool_step provenance_write timeout'),
  ];
  return source.includes('const compilerCause = value => {') &&
    source.includes('const scenarioFailure = value => {') &&
    source.includes('const stepFailure = (stderrValue, stdoutValue) => {') &&
    source.includes('const combined = `${String(stderrValue).slice(-65536)}\\n${String(stdoutValue).slice(-65536)}`;') &&
    source.includes('const markers = combined.split(/\\r?\\n/).filter(line => line.startsWith("SHARED_POOL_STEP_FAIL:"));') &&
    source.includes('if (markers.length !== 1) return "";') &&
    source.includes('status <= 255') &&
    source.includes('stepPhases.includes(match[1])') &&
    source.includes(`const sourceFiles = ${JSON.stringify(compilerSourceFiles)};`) &&
    source.includes(`const stepPhases = ${JSON.stringify(sharedPoolBuildPhases)};`) &&
    source.includes('lineNumber > 100000') &&
    compilerErrorClasses.every(category => source.includes(`'${category}'`)) &&
    sharedPoolBuildPhases.filter(phase => phase !== 'source_union').every(phase => source.includes(`run_shared_pool_step ${phase}`)) &&
    source.includes(sharedPoolStepGuard) &&
    source.includes('run_shared_pool_step base_builder bash "$builder" "$work" "$patch_file" "$work/provenance.json"') &&
    source.includes('run_shared_pool_step apply_check timeout --signal=TERM --kill-after=5s 30s git -C "$work/source" apply --check ') &&
    source.includes('run_shared_pool_step apply_0002 timeout --signal=TERM --kill-after=5s 30s git -C "$work/source" apply ') &&
    source.includes(sourceUnionFailureGuard) &&
    source.includes('if [[ "$actual_union" == "$expected_union" ]]') &&
    source.includes('SHARED_POOL_STEP_FAIL:source_union:%s') &&
    source.includes('run_shared_pool_step cmake_rebuild timeout --signal=TERM --kill-after=5s 600s cmake --build "$work/build" --target llama-server --parallel 2') &&
    source.includes('run_shared_pool_step provenance_write timeout --signal=TERM --kill-after=5s 30s python3 - ') &&
    source.includes(`const selectedCause = scenarioFailure(stdout) || compilerCause(stderr) || compilerCause(stdout) || stepFailure(stderr, stdout) || pythonCause(stderr)`) &&
    source.includes(`${JSON.stringify(requiredNames)}.includes(name)`) &&
    phaseOrder.every((position, index) => position >= 0 && (index === 0 || position > phaseOrder[index - 1]));
}

function transformedRunnerSource() {
  verifyFrozenPins();
  const oldPath = path.join(repo, 'scripts/checkpoint-compat/verify-cpu-descriptor.mjs');
  let source = readFileSync(oldPath, 'utf8');
  source = replaceExactlyOnce(source,
    "const here = path.dirname(fileURLToPath(import.meta.url));",
    `const here = ${JSON.stringify(path.join(repo, 'scripts/checkpoint-compat'))};`, 'runner base path');
  source = replaceExactlyOnce(source,
    "const mode = process.argv[2] === '--controls' ? 'controls' : 'cpu';",
    "const mode = 'shared-pool';", 'fixed CPU mode');
  source = replaceExactlyOnce(source,
    '    env = os.environ.copy()\n',
    "    env = os.environ.copy()\n    env.pop('LLAMA_CHECKPOINT_COMPAT_SHARED_POOL', None)\n", 'fixed default-off environment');
  assert(source.split("const patch = path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0001-checkpoint-compat-descriptor.patch');").length - 1 === 1,
    'frozen base patch input anchor changed');
  const generatorPathAnchor = 'const generatorWsl = wslPath(generator);\n';
  source = replaceExactlyOnce(source, generatorPathAnchor,
    generatorPathAnchor + "const sharedPoolPatchWsl = wslPath(path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0002-initialized-shared-pool.patch'));\n",
    'shared-pool patch path after bounded WSL preflight');
  source = replaceExactlyOnce(source,
    "def request(p, method='GET', route='/checkpoint/compat', body=None):",
    "def request(p, method='GET', route='/checkpoint/compat', body=None, timeout=2):", 'bounded HTTP request helper signature');
  source = replaceExactlyOnce(source,
    'with urllib.request.urlopen(req, timeout=2) as response:',
    'with urllib.request.urlopen(req, timeout=timeout) as response:', 'bounded HTTP request helper timeout');
  source = replaceExactlyOnce(source,
    "    data = None if body is None else json.dumps(body, separators=(',', ':')).encode()\n",
    "    data = None if body is None else (body.encode() if isinstance(body, str) else json.dumps(body, separators=(',', ':')).encode())\n",
    'bounded raw JSON payload controls');
  const failureSummaryAnchor = '  const selectedCause = pythonCause(stderr) || pythonCause(stdout) || otherCause(stderr) || otherCause(stdout);\n';
  const failureSummaryHelpers = [
    '  const compilerCause = value => {',
    `    const sourceFiles = ${JSON.stringify(compilerSourceFiles)};`,
    '    for (const line of String(value).slice(-65536).split(/\\r?\\n/).reverse()) {',
    "      const normalized = line.replaceAll('\\\\', '/');",
    '      for (const file of sourceFiles) {',
    "        const index = normalized.lastIndexOf(file + ':');",
    '        if (index < 0) continue;',
    '        const match = normalized.slice(index + file.length + 1).match(/^(\\d+)(?::\\d+)?:\\s*(?:fatal\\s+)?error:\\s*(.*)$/i);',
    '        if (!match) continue;',
    '        const lineNumber = Number(match[1]);',
    '        if (!Number.isInteger(lineNumber) || lineNumber < 1 || lineNumber > 100000) continue;',
    '        const body = match[2].toLowerCase();',
    "        const category = /no member named|has no member named|is not a member/.test(body) ? 'missing_member' : /not declared|undeclared|undefined reference|unknown type name|does not name a type/.test(body) ? 'missing_symbol' : /cannot convert|incompatible|invalid conversion|cannot initialize|no viable conversion|cannot bind|ambiguous/.test(body) ? 'type_mismatch' : /expected .*?(?:before|token|\\x27;\\x27)|stray .*?(?:\\\\\\\\|character)|parse error/.test(body) ? 'syntax_error' : 'other_compile_error';",
    "        return 'compile_error ' + file + ':' + lineNumber + ' ' + category;",
    '      }',
    '    }',
    "    return '';",
    '  };',
    '  const scenarioFailure = value => {',
    "    const failed = lines(value).filter(line => /^FAIL [a-z0-9-]+$/.test(line)).at(-1);",
    '    if (!failed) return "";',
    '    const name = failed.slice(5);',
    `    return ${JSON.stringify(requiredNames)}.includes(name) ? 'shared_pool_scenario:' + name : '';`,
    '  };',
    '  const stepFailure = (stderrValue, stdoutValue) => {',
    '    const combined = `${String(stderrValue).slice(-65536)}\\n${String(stdoutValue).slice(-65536)}`;',
    '    const markers = combined.split(/\\r?\\n/).filter(line => line.startsWith("SHARED_POOL_STEP_FAIL:"));',
    '    if (markers.length !== 1) return "";',
    '    const match = markers[0].match(/^SHARED_POOL_STEP_FAIL:([a-z0-9_]+):(0|[1-9]\\d{0,2})$/);',
    '    if (!match) return "";',
    `    const stepPhases = ${JSON.stringify(sharedPoolBuildPhases)};`,
    '    const status = Number(match[2]);',
    "    return stepPhases.includes(match[1]) && Number.isInteger(status) && status >= 0 && status <= 255 ? 'shared_pool_step:' + match[1] + ':' + status : '';",
    '  };',
  ].join('\n') + '\n';
  source = replaceExactlyOnce(source, failureSummaryAnchor,
    failureSummaryHelpers + '  const selectedCause = scenarioFailure(stdout) || compilerCause(stderr) || compilerCause(stdout) || stepFailure(stderr, stdout) || pythonCause(stderr) || pythonCause(stdout) || otherCause(stderr) || otherCause(stdout);\n',
    'finite scenario, compiler, and shared-pool phase failure diagnostics');
  const cleanupSupervisorAnchor = "if mode == 'controls':\n    sentinel_parent_pid = os.getpid()\n";
  source = replaceExactlyOnce(source, cleanupSupervisorAnchor,
    "if mode in ('controls', 'shared-pool'):\n    sentinel_parent_pid = os.getpid()\n", 'shared-pool cleanup supervisor guard');
  source = replaceExactlyOnce(source,
    'bash "$builder" "$work" "$patch_file" "$work/provenance.json"\n',
    'run_shared_pool_step() {\n' +
    '  local phase=$1 status\n' +
    '  shift\n' +
    '  case "$phase" in\n' +
    '    base_builder|apply_check|apply_0002|source_union|cmake_rebuild|provenance_write) ;;\n' +
    '    *) exit 125 ;;\n' +
    '  esac\n' +
    '  if "$@"; then\n' +
    '    return 0\n' +
    '  else\n' +
    '    status=$?\n' +
    '    printf \'SHARED_POOL_STEP_FAIL:%s:%s\\n\' "$phase" "$status" >&2\n' +
    '    exit "$status"\n' +
    '  fi\n' +
    '}\n' +
    'run_shared_pool_step base_builder bash "$builder" "$work" "$patch_file" "$work/provenance.json"\n' +
    'run_shared_pool_step apply_check timeout --signal=TERM --kill-after=5s 30s git -C "$work/source" apply --check ' + '${shellQuote(sharedPoolPatchWsl)}' + '\n' +
    'run_shared_pool_step apply_0002 timeout --signal=TERM --kill-after=5s 30s git -C "$work/source" apply ' + '${shellQuote(sharedPoolPatchWsl)}' + '\n' +
    'expected_union="include/llama.h|src/llama-context.cpp|src/llama-kv-cache.cpp|src/llama-kv-cache.h|tools/server/server-context.cpp|tools/server/server-context.h|tools/server/server-queue.cpp|tools/server/server-queue.h|tools/server/server-task.h|tools/server/server.cpp"\n' +
    'if actual_union=$(git -C "$work/source" diff --name-only | tr "\\n" "|" | sed "s/|$//"); then :; else status=$?; printf \'SHARED_POOL_STEP_FAIL:source_union:%s\\n\' "$status" >&2; exit "$status"; fi\n' +
    'if [[ "$actual_union" == "$expected_union" ]]; then :; else status=$?; printf \'SHARED_POOL_STEP_FAIL:source_union:%s\\n\' "$status" >&2; printf "shared-pool: combined patch union mismatch\\n" >&2; exit "$status"; fi\n' +
    'run_shared_pool_step cmake_rebuild timeout --signal=TERM --kill-after=5s 600s cmake --build "$work/build" --target llama-server --parallel 2\n' +
    'run_shared_pool_step provenance_write timeout --signal=TERM --kill-after=5s 30s python3 - "$work/source" ' + '${shellQuote(sharedPoolPatchWsl)}' + ' "$work/build/bin/llama-server" "$work/shared-pool-provenance.json" <<\'PY\'\n' +
    'import hashlib,json,pathlib,subprocess,sys\n' +
    'source,patch,binary,out=map(pathlib.Path,sys.argv[1:])\n' +
    'digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()\n' +
    'names=subprocess.run(["git","-C",str(source),"diff","--name-only"],check=True,text=True,capture_output=True,timeout=10).stdout.splitlines()\n' +
    'expected="include/llama.h|src/llama-context.cpp|src/llama-kv-cache.cpp|src/llama-kv-cache.h|tools/server/server-context.cpp|tools/server/server-context.h|tools/server/server-queue.cpp|tools/server/server-queue.h|tools/server/server-task.h|tools/server/server.cpp".split("|")\n' +
    'if names!=expected: raise SystemExit("shared-pool provenance source union mismatch")\n' +
    'payload={"pinnedCommit":"62acc89c26c66076cb72e049f307fbe93b8b9750","patch0002Sha256":digest(patch),"serverSha256":digest(binary),"combinedSourcePaths":names}\n' +
    'out.write_text(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\\n",encoding="utf-8")\n' +
    'PY\n', 'apply exact 0002 after 0001 and rebuild');
  assert(hasFailureDiagnosticTransform(source), `bounded failure diagnostic transform is incomplete; missing phases=${sharedPoolBuildPhases.filter(phase => !source.includes(`run_shared_pool_step ${phase}`)).join(',') || 'none'}; helper=${source.includes('run_shared_pool_step() {')}; enum=${source.includes('base_builder|apply_check|apply_0002|source_union|cmake_rebuild|provenance_write) ;;')}; statusGuard=${source.includes('if "$@"; then') && source.includes('exit "$status"')}; marker=${source.includes('SHARED_POOL_STEP_FAIL:%s:%s')}; unionMarker=${source.includes('SHARED_POOL_STEP_FAIL:source_union:%s')}; compilerBranch=${source.includes('compilerCause(stderr) ||')}`);
  const missingCompilerBranch = source.replace('compilerCause(stderr) || ', '');
  assert(!hasFailureDiagnosticTransform(missingCompilerBranch), 'failure diagnostic source control accepted a missing compiler-cause branch');
  const missingPhase = source.replace('run_shared_pool_step apply_check timeout ', 'timeout ');
  assert(!hasFailureDiagnosticTransform(missingPhase), 'failure diagnostic source control accepted a missing build phase marker');
  const missingFailureExitGuard = source.replace('    exit "$status"\n  fi\n}', '    return "$status"\n  fi\n}');
  assert(!hasFailureDiagnosticTransform(missingFailureExitGuard), 'failure diagnostic source control accepted a missing original-status exit guard');
  const missingUnionFailureMarker = source.replace(
    String.raw`printf 'SHARED_POOL_STEP_FAIL:source_union:%s\n' "$status" >&2;`,
    '',
  );
  assert(!hasFailureDiagnosticTransform(missingUnionFailureMarker), 'failure diagnostic source control accepted a missing source-union pipeline-failure marker');
  const changedUnionFailureStatus = source.replace(
    sourceUnionFailureGuard,
    sourceUnionFailureGuard.replace('exit "$status"; fi', 'exit 1; fi'),
  );
  assert(!hasFailureDiagnosticTransform(changedUnionFailureStatus), 'failure diagnostic source control accepted a source-union status that was not preserved');
  const unknownPhaseEnum = source.replace('base_builder|apply_check|apply_0002|source_union|cmake_rebuild|provenance_write', 'base_builder|apply_check|apply_0002|source_union|cmake_rebuild|unsafe_phase');
  assert(!hasFailureDiagnosticTransform(unknownPhaseEnum), 'failure diagnostic source control accepted an unknown phase enum');
  const cpuBranch = /    if mode == 'cpu':[\s\S]*?(?=    elif mode == 'controls':)/;
  assert((source.match(/    if mode == 'cpu':/g) || []).length === 1 && cpuBranch.test(source), 'frozen runner CPU scenario anchor changed');
  source = source.replace(cpuBranch, `    if mode == 'shared-pool':
        def shared_launch(cap=None):
            extra = ('--kv-unified', '--no-cache-idle-slots', '--slots', '--slot-save-path', str(root / 'slot-saves') + '/')
            if cap is not None:
                extra += ('--kv-unified-per-slot', str(cap))
            (root / 'slot-saves').mkdir(exist_ok=True)
            return launch(1024, 4, True, extra=extra, env_extra={'LLAMA_CHECKPOINT_COMPAT_SHARED_POOL': '1'})
        def snapshot(p, timeout=2):
            status, raw = request(p, route='/checkpoint/shared-pool', timeout=timeout)
            if status != 200 or len(raw) > 65536:
                raise RuntimeError('shared-pool snapshot did not return bounded 200')
            value = json.loads(raw)
            if set(value) != {'schemaVersion', 'support', 'incarnation', 'epoch', 'pool', 'slots'} or value['schemaVersion'] != 1 or value['support'] != 'initialized-unified-plain-llama-kv':
                raise RuntimeError('shared-pool snapshot schema/support mismatch')
            pool = value['pool']
            if set(pool) != {'initialized', 'totalCells', 'usedCells', 'freeCells', 'unattributedCells'}:
                raise RuntimeError('shared-pool physical count fields are incomplete')
            if not pool.get('initialized') or pool['totalCells'] <= 0 or pool['usedCells'] + pool['freeCells'] != pool['totalCells'] or len(value['slots']) != 4:
                raise RuntimeError('physical cell accounting or slot inventory mismatch')
            if not re.fullmatch(r'[0-9a-f]{32}', value['incarnation']) or not re.fullmatch(r'0|[1-9][0-9]{0,19}', value['epoch']):
                raise RuntimeError('pool incarnation/decimal epoch is not canonical')
            return value
        def completion(p, slot, count, seed, n_predict=4, ignore_eos=False):
            prompt = [((seed + i) % 8) for i in range(count)]
            payload = {'prompt': prompt, 'n_predict': n_predict, 'id_slot': slot}
            if ignore_eos: payload['ignore_eos'] = True
            status, body = request(p, 'POST', '/completion', payload, timeout=30)
            if status != 200:
                raise RuntimeError('explicit numeric-token completion failed: ' + body.decode(errors='replace')[:160])
            result = json.loads(body)
            if result.get('id_slot') != slot or result.get('truncated') is not False or not isinstance(result.get('tokens_evaluated'), int) or result['tokens_evaluated'] < count or not isinstance(result.get('tokens_predicted'), int) or result['tokens_predicted'] <= 0:
                raise RuntimeError('completion response did not prove requested slot, evaluated prompt, generated tokens and no truncation')
            if ignore_eos and result['tokens_predicted'] < n_predict:
                raise RuntimeError('ignore_eos completion ended before the requested active window')
            return result
        def pool_clear(p, value, slot, incarnation=None, epoch=None):
            return request(p, 'POST', '/checkpoint/shared-pool/clear', {
                'slot': slot, 'incarnation': value['incarnation'] if incarnation is None else incarnation,
                'epoch': value['epoch'] if epoch is None else epoch})
        def stop_if_live():
            if child is not None:
                stop()
        state = {}
        def zero_pool():
            p, start = shared_launch(); value = snapshot(p)
            state.update(p=p, start=start, initial=value)
            if request(p, route='/checkpoint/compat')[0] != 409: raise RuntimeError('legacy descriptor route remained live in shared-pool mode')
            if value['pool']['usedCells'] != 0 or any(s['membershipCells'] != 0 for s in value['slots']): raise RuntimeError('fresh initialized pool is not empty')
        run_case('initialized-zero-pool', zero_pool)
        def four_retained():
            p = state['p']
            for slot in range(4): completion(p, slot, 192, slot + 1)
            value = snapshot(p)
            if [s['membershipCells'] >= 192 for s in value['slots']] != [True] * 4 or value['pool']['usedCells'] < 768:
                raise RuntimeError('four distinct numeric token sequences did not retain at least the requested prompt contexts')
            state['four'] = value
        run_case('four-retained-distinct-sequences', four_retained)
        def busy_clear():
            p = state['p']; before = snapshot(p)
            import threading
            worker_result = {}; worker_error = {}
            def run_completion():
                try:
                    worker_result['response'] = completion(p, 0, 192, 6, n_predict=200, ignore_eos=True)
                except BaseException as error:
                    worker_error['error'] = error
            worker = threading.Thread(target=run_completion, daemon=True)
            worker.start()
            deadline = time.monotonic() + 10; active = None
            while time.monotonic() < deadline:
                status, raw = request(p, route='/slots')
                if status == 200 and any(slot.get('id') == 0 and slot.get('is_processing') for slot in json.loads(raw)):
                    current = snapshot(p, timeout=10)
                    if current['slots'][0]['state'] == 'active': active = current; break
                if worker_error: break
                time.sleep(0.01)
            if active is None:
                worker.join(timeout=30)
                raise RuntimeError('shared-pool owner-thread snapshot never proved the selected slot active')
            if int(active['epoch']) != int(before['epoch']) + 1: raise RuntimeError('active snapshot did not carry the post-selection epoch')
            status, raw = pool_clear(p, active, 0)
            error_body = json.loads(raw)
            if status != 409 or b'stale' in raw.lower() or 'active' not in json.dumps(error_body).lower():
                raise RuntimeError('current-epoch clear did not fail specifically on active slot/work')
            after = snapshot(p, timeout=10)
            if after['epoch'] != active['epoch'] or after['slots'][0]['state'] != 'active' or after['slots'][0]['membershipCells'] == 0 or any(after['slots'][i]['membershipCells'] != active['slots'][i]['membershipCells'] for i in range(1, 4)):
                raise RuntimeError('busy clear changed pool epoch or other retained sequences')
            worker.join(timeout=30)
            if worker.is_alive() or worker_error or worker_result.get('response', {}).get('id_slot') != 0 or worker_result.get('response', {}).get('tokens_evaluated', 0) < 192 or worker_result.get('response', {}).get('tokens_predicted', 0) < 200:
                raise RuntimeError('physically bounded active completion response did not settle: ' + str(worker_error.get('error')))
        run_case('busy-clear-rejected-unchanged', busy_clear)
        def wrong_pool_epoch():
            p = state['p']; value = snapshot(p); before = value.copy()
            if pool_clear(p, value, 0, incarnation='0' * 32)[0] != 409: raise RuntimeError('wrong pool incarnation accepted')
            if pool_clear(p, value, 0, epoch=str(int(value['epoch']) + 1))[0] != 409: raise RuntimeError('wrong pool epoch accepted')
            after = snapshot(p)
            if (after['epoch'], after['pool'], after['slots']) != (before['epoch'], before['pool'], before['slots']): raise RuntimeError('stale rejection changed pool snapshot')
        run_case('wrong-pool-epoch-rejected-unchanged', wrong_pool_epoch)
        def wrong_slot_epoch():
            p = state['p']; old = state['initial']
            if pool_clear(p, old, 1)[0] != 409: raise RuntimeError('pre-selection slot epoch accepted')
            if snapshot(p)['slots'][1]['membershipCells'] == 0: raise RuntimeError('wrong-slot epoch check lacked retained sequence')
            before = snapshot(p)
            def clear_payload(slot):
                return {'slot':slot, 'incarnation':before['incarnation'], 'epoch':before['epoch']}
            invalid = [
                clear_payload(-1), clear_payload(64), clear_payload(18446744073709551615),
                clear_payload(18446744073709551616), clear_payload(0.5), clear_payload('0'),
                dict(clear_payload(0), extra=True), {'slot':0, 'incarnation':before['incarnation']},
                {'slot':0, 'incarnation':0, 'epoch':before['epoch']},
                {'slot':0, 'incarnation':before['incarnation'], 'epoch':0},
                '{"slot":', ' ' * 513,
            ]
            for payload in invalid:
                status, _ = request(p, 'POST', '/checkpoint/shared-pool/clear', payload)
                if status != 400: raise RuntimeError('invalid exact-clear payload was not rejected before enqueue')
            after = snapshot(p)
            if (after['epoch'], after['pool'], after['slots']) != (before['epoch'], before['pool'], before['slots']):
                raise RuntimeError('invalid exact-clear payload changed pool state')
        run_case('wrong-slot-epoch-rejected-unchanged', wrong_slot_epoch)
        def selective_clear():
            p = state['p']; before = snapshot(p); old = before['epoch']
            status, receipt_raw = pool_clear(p, before, 0)
            after = snapshot(p)
            if status != 200 or after['slots'][0]['membershipCells'] != 0 or any(after['slots'][i]['membershipCells'] != before['slots'][i]['membershipCells'] for i in range(1, 4)) or after['epoch'] == old:
                raise RuntimeError('selective clear failed exact target or preserved other memberships')
            receipt = json.loads(receipt_raw)
            if receipt.get('schemaVersion') != 1 or receipt.get('cleared') is not True or receipt.get('slot') != 0 or receipt.get('membershipCells') != 0 or receipt.get('incarnation') != after['incarnation'] or receipt.get('epoch') != after['epoch']:
                raise RuntimeError('clear receipt did not acknowledge the exact pool/slot/epoch')
            if receipt.get('pool') != {key: after['pool'][key] for key in ('totalCells', 'usedCells', 'freeCells', 'unattributedCells')}:
                raise RuntimeError('clear receipt physical counts differ from settled snapshot')
            state['cleared'] = before
        run_case('selective-clear-preserves-other-sequences', selective_clear)
        def replay():
            p = state['p']; old = state['cleared']; before = snapshot(p)
            if pool_clear(p, old, 0)[0] != 409: raise RuntimeError('clear replay accepted')
            after = snapshot(p)
            if (after['epoch'], after['pool'], after['slots']) != (before['epoch'], before['pool'], before['slots']): raise RuntimeError('clear replay changed current pool')
        run_case('clear-replay-rejected', replay)
        def lifecycle():
            p = state['p']; completion(p, 0, 32, 2); before = snapshot(p)
            status, _ = request(p, 'POST', '/slots/0?action=save', {'filename':'slot.bin'})
            if status != 200: raise RuntimeError('fixed slot save failed')
            status, _ = request(p, 'POST', '/slots/0?action=restore', {'filename':'slot.bin'})
            restored = snapshot(p)
            if status != 200 or int(restored['epoch']) <= int(before['epoch']): raise RuntimeError('restore did not fence epoch')
            status, _ = request(p, 'POST', '/slots/0?action=erase', {})
            erased = snapshot(p)
            if status != 200 or int(erased['epoch']) <= int(restored['epoch']): raise RuntimeError('erase did not fence epoch')
        run_case('load-restore-erase-clear-epoch-fence', lifecycle)
        def short_long():
            p = state['p']; identity = (child.pid, child_start, state['start'], state['initial']['incarnation'])
            for slot in (1, 2, 3):
                value = snapshot(p); status, _ = pool_clear(p, value, slot)
                if status != 200: raise RuntimeError('idle sequence clear failed before long request')
            long_result = completion(p, 0, 768, 3)
            after = snapshot(p)
            if after['slots'][0]['membershipCells'] < 768 or after['slots'][0]['effectiveContextCap'] < 768 or long_result['tokens_evaluated'] < 768:
                raise RuntimeError('long request did not consume 768 prompt tokens within its effective slot cap')
            if (child.pid, child_start, state['start'], after['incarnation']) != identity or proc_start(child.pid) != state['start']:
                raise RuntimeError('short-to-long transition replaced process/pool incarnation')
            listener_inode(child.pid, p)
            state['long'] = after
        run_case('uncapped-short-to-long-same-worker', short_long); stop_if_live()
        def same_server():
            prior_incarnation = state['initial']['incarnation']
            p, _ = shared_launch(); before = snapshot(p); identity = (child.pid, child_start)
            if before['incarnation'] == prior_incarnation: raise RuntimeError('fresh initialized pool reused the prior incarnation')
            completion(p, 0, 192, 4); mid = snapshot(p); completion(p, 0, 768, 5); after = snapshot(p)
            if mid['slots'][0]['membershipCells'] < 192 or after['slots'][0]['membershipCells'] < 768 or after['slots'][0]['effectiveContextCap'] < 768:
                raise RuntimeError('same-server short-to-long contexts were not retained within actual effective cap')
            if (child.pid, child_start) != identity or before['incarnation'] != mid['incarnation'] or mid['incarnation'] != after['incarnation']:
                raise RuntimeError('same-server transition changed child or pool nonce')
            if proc_start(child.pid) != child_start: raise RuntimeError('same-server process start identity changed')
            listener_inode(child.pid, p)
        run_case('same-process-listener-incarnation', same_server); stop_if_live()
        def optout():
            p, _ = launch(1024, 4, True, extra=('--kv-unified', '--no-cache-idle-slots'))
            if request(p, route='/checkpoint/shared-pool')[0] != 404: raise RuntimeError('new pool route is not default-off')
            if request(p, route='/checkpoint/compat')[0] != 200: raise RuntimeError('pool opt-out changed frozen descriptor behavior')
        run_case('opt-out-default-off', optout); stop_if_live()
        def nonunified():
            p, _ = launch(1024, 4, True, extra=('--no-kv-unified', '--no-cache-idle-slots'), env_extra={'LLAMA_CHECKPOINT_COMPAT_SHARED_POOL': '1'})
            if request(p, route='/checkpoint/shared-pool')[0] != 409: raise RuntimeError('partitioned KV was not rejected')
        run_case('nonunified-rejected', nonunified); stop_if_live()
        def cap_negative():
            p, _ = shared_launch(192)
            value = snapshot(p)
            if any(slot['effectiveContextCap'] > 192 for slot in value['slots']): raise RuntimeError('per-slot cap was not reflected')
            status, body = request(p, 'POST', '/completion', {'prompt':[1]*768, 'n_predict':4, 'id_slot':0})
            if status < 400: raise RuntimeError('over-cap long context was accepted')
        run_case('slot-cap-long-context-rejected', cap_negative); stop_if_live()
`);
  const controlsAnchor = "if (mode === 'controls') {";
  assert(source.split(controlsAnchor).length - 1 === 1, 'frozen runner cleanup branch transformation count changed');
  const cleanupLogAnchor = "if (mode === 'controls') console.log(cleanupMarkers.join('\\n'));";
  assert(source.split(cleanupLogAnchor).length - 1 === 1, 'frozen runner cleanup marker log transformation count changed');
  assert((source.match(/    if mode == 'shared-pool':/g) || []).length === 1, 'shared-pool branch transformation count changed');
  const expectedAnchor = /const expected = mode === 'cpu' \? \['initialized-supported-descriptor'\] : \[/;
  assert((source.match(expectedAnchor) || []).length === 1, 'frozen runner transformation anchor changed: exact shared-pool inventory');
  source = source.replace(expectedAnchor, `const expected = mode === 'shared-pool' ? ${JSON.stringify(requiredNames)} : [`);
  source = source.replaceAll(controlsAnchor, "if (mode === 'controls' || mode === 'shared-pool') {");
  source = replaceExactlyOnce(source, cleanupLogAnchor,
    "if (mode === 'controls' || mode === 'shared-pool') console.log(cleanupMarkers.join('\\n'));", 'cleanup marker log mode');
  const completionAnchor = /console\.log\(mode === 'cpu' \? 'checkpoint backend descriptor CPU verification passed' : 'checkpoint backend descriptor controls verification passed'\);/;
  assert((source.match(completionAnchor) || []).length === 1, 'frozen runner transformation anchor changed: CPU completion message');
  source = source.replace(completionAnchor, "console.log('initialized shared pool CPU controls passed');");
  assertSharedPoolCleanupSupervisor(source);
  let missingCleanupGuardRejected = false;
  try {
    assertSharedPoolCleanupSupervisor(source.replace(
      "if mode in ('controls', 'shared-pool'):\n    sentinel_parent_pid = os.getpid()",
      "if mode == 'controls':\n    sentinel_parent_pid = os.getpid()"));
  } catch (error) { missingCleanupGuardRejected = String(error?.message || error).includes('shared-pool mode does not reach'); }
  assert(missingCleanupGuardRejected, 'cleanup-supervisor source control accepted a missing shared-pool mode guard');
  assertSharedPoolInitializationOrder(source);
  const patchDeclaration = "const sharedPoolPatchWsl = wslPath(path.join(repo, 'patches/llama.cpp/62acc89c26c66076cb72e049f307fbe93b8b9750/0002-initialized-shared-pool.patch'));";
  const earlyPlacementMutant = source.replace(patchDeclaration + '\n', '').replace('const limit = 1024 * 1024;', patchDeclaration + '\nconst limit = 1024 * 1024;');
  let earlyPlacementRejected = false;
  try { assertSharedPoolInitializationOrder(earlyPlacementMutant); }
  catch (error) { earlyPlacementRejected = String(error?.message || error).includes('initialize after maxBuffer'); }
  assert(earlyPlacementRejected, 'patch-path initialization-order source control accepted an early wslPath call');
  return source;
}

function verifyCpu() {
  const transformed = transformedRunnerSource();
  const result = spawnSync(process.execPath, ['--input-type=module', '-'], {
    cwd: repo, input: transformed, encoding: 'utf8', timeout: 1_080_000, maxBuffer: 1024 * 1024, windowsHide: true,
  });
  if (result.error || result.status !== 0) {
    console.error(summarizeCpuFailure(result));
    process.exitCode = Number.isInteger(result.status) && result.status > 0 && result.status <= 255 ? result.status : 1;
    return;
  }
  process.stdout.write(result.stdout);
}

if (process.argv.length !== 3 || !['--source', '--cpu'].includes(process.argv[2])) {
  console.error('usage: node verify-cpu-shared-pool.mjs --source|--cpu');
  process.exit(2);
}
if (process.argv[2] === '--source') verifySource();
else verifyCpu();
