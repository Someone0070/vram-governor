import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2];
const maxSourceBytes = 2 << 20;
const owned = [
  'internal/api/http.go',
  'internal/api/workloads_http_test.go',
  'internal/workloads/manager.go',
  'internal/workloads/manager_test.go',
  'internal/api/comfy_discovery_http.go',
  'internal/api/comfy_discovery_http_test.go',
  'internal/workloads/comfy_discovery.go',
  'internal/workloads/comfy_discovery_test.go',
  'scripts/verify-comfy-fleet-discovery.mjs',
];

const protocolParents = [
  'TestComfyFleetDiscoveryAuthorization',
  'TestComfyFleetDiscoveryFixedRoutes',
  'TestComfyFleetDiscoveryMixedProtocols',
  'TestComfyFleetDiscoveryConflictsAndStats',
  'TestWorkloadAuthPriorityClampAndOwnership',
  'TestSecurityPlaneCannotBeBypassedWithWildcardScope',
  'TestArtifactReferencesAreOwnerScopedBeforeAdmission',
];
const placementParents = [
  'TestComfyFleetDiscoveryEligibility',
  'TestComfyFleetDiscoveryTransportBounds',
  'TestComfyFleetGraphValidation',
  'TestComfyFleetGraphSingleCandidate',
  'TestComfyFleetGraphBestFit',
  'TestComfyFleetGraphAdmissionSpillsBusyInvalidAndOffline',
  'TestComfyFleetGraphAdmissionRejectsCrossMachineGraphWithoutPost',
  'TestComfyFleetGraphAdmissionGenerationFence',
  'TestComfyFleetGraphPreStartSchemaFence',
  'TestComfyFleetGraphNoLocksAcrossFetch',
  'TestComfyProgressObserverIgnoresBinaryPreviewFrames',
  'TestManagedComfyLifecycle',
  'TestManagedComfyRejectsAmbiguousState',
  'TestTargetSpecificDisruptionSelectsManagedComfy',
  'TestRuntimeProtocolChangesPlanHash',
  'TestManagedComfyChunksRequireManagedProtocolAndAggregateRequirements',
  'TestLLMAndComfyShareOnePhysicalLease',
  'TestComfyPromptMappingTracksTargetAndBackendWithoutOverwriteRace',
  'TestComfyStagesCentralInputsAndCollectsOutputs',
  'TestBuiltInAdaptersRejectUnimplementedDisruptionPromises',
  'TestComfyRequirementsAreInferredFromWorkflowLoadersAndNodeClasses',
  'TestComfyTransformationPlanContainsMaterialChangeAndRequiresProof',
  'TestContextBestFitPreservesLargeContextTarget',
  'TestContextBestFitBeatsResidentLongProfile',
  'TestStickyPlacementDoesNotSpillClientToLargerTarget',
  'TestTargetExecutionFingerprintCoversDispatchAndCapacityFacts',
  'TestAdmissionOwnedPlacementGenerationHandoff',
];
const goPackages = {
  './internal/api': 'vram-governor/internal/api',
  './internal/workloads': 'vram-governor/internal/workloads',
};

function expectedGoPackage(packagePath) {
  const value = goPackages[packagePath];
  if (!value) throw new Error(`unknown Go package selector: ${packagePath}`);
  return value;
}

function readOwned() {
  const files = new Map();
  for (const relative of owned) {
    const absolute = path.resolve(root, relative);
    if (!absolute.startsWith(root + path.sep)) throw new Error(`unsafe owned path: ${relative}`);
    const stat = fs.lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 0 || stat.size > maxSourceBytes) throw new Error(`source file is not a bounded regular file: ${relative}`);
    const fd = fs.openSync(absolute, 'r');
    try {
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.size !== stat.size || opened.size > maxSourceBytes) throw new Error(`source file changed before bounded read: ${relative}`);
      const buffer = Buffer.alloc(stat.size + 1);
      const count = fs.readSync(fd, buffer, 0, buffer.length, 0);
      if (count !== stat.size) throw new Error(`source file changed during bounded read: ${relative}`);
      files.set(relative, buffer.subarray(0, count).toString('utf8'));
    } finally { fs.closeSync(fd); }
  }
  return files;
}

function declaredTests(source) {
  return [...source.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
}

function exactInventory(files, pathName, expected) {
  const found = declaredTests(files.get(pathName));
  for (const name of found) {
    if (!expected.includes(name)) throw new Error(`foreign top-level test ${name} in ${pathName} verifier inventory`);
  }
  if (new Set(found).size !== found.length) throw new Error(`duplicate top-level test in ${pathName}`);
  if (found.length !== expected.length || found.some((name, index) => name !== expected[index])) throw new Error(`test inventory is missing, duplicated, or out of declaration order in ${pathName}`);
  return found;
}

function sourceOnly() {
  const files = readOwned();
  const http = files.get('internal/api/http.go');
  const handlers = files.get('internal/api/comfy_discovery_http.go');
  const manager = files.get('internal/workloads/manager.go');
  const discovery = files.get('internal/workloads/comfy_discovery.go');
  for (const route of ['GET /object_info', 'GET /system_stats']) {
    if (!http.includes(route)) throw new Error(`missing fixed public route ${route}`);
  }
  for (const token of ['comfy:read', 'allowsAdapter(p, "comfy")', 'RawQuery', 'ForceQuery', 'ComfyFleetDiscovery']) {
    if (!handlers.includes(token)) throw new Error(`missing public discovery guard ${token}`);
  }
  for (const token of ['ComfySchema(ctx, target', 'reservation.comfySchemaProof', 'graphDigest', 'validateComfyRequestSchema']) {
    if (!manager.includes(token) && !discovery.includes(token)) throw new Error(`missing candidate validation seam ${token}`);
  }
  for (const token of ['comfyFetchTimeout', 'comfyFleetTimeout', 'comfyMaxTargets', 'comfyMaxConcurrent', 'CheckRedirect', 'comfyObjectInfoLimit', 'comfyStatsLimit']) {
    if (!discovery.includes(token)) throw new Error(`missing bounded fetch control ${token}`);
  }
  exactInventory(files, 'internal/api/comfy_discovery_http_test.go', protocolParents.slice(0, 4));
  exactInventory(files, 'internal/workloads/comfy_discovery_test.go', placementParents.slice(0, 10));
  if (!files.get('internal/api/workloads_http_test.go').includes('func TestWorkloadAuthPriorityClampAndOwnership(')) throw new Error('existing API route assertion disappeared');
  if (!files.get('internal/workloads/manager_test.go').includes('func TestComfyRequirementsAreInferredFromWorkflowLoadersAndNodeClasses(')) throw new Error('existing Comfy requirements assertion disappeared');
  assertOrderedSubsequence(declaredTests(files.get('internal/api/workloads_http_test.go')), protocolParents.slice(4), 'API regression inventory');
  assertOrderedSubsequence(declaredTests(files.get('internal/workloads/manager_test.go')), [
    'TestLLMAndComfyShareOnePhysicalLease',
    'TestComfyPromptMappingTracksTargetAndBackendWithoutOverwriteRace',
    'TestComfyStagesCentralInputsAndCollectsOutputs',
    'TestBuiltInAdaptersRejectUnimplementedDisruptionPromises',
    'TestComfyRequirementsAreInferredFromWorkflowLoadersAndNodeClasses',
    'TestComfyTransformationPlanContainsMaterialChangeAndRequiresProof',
    'TestContextBestFitPreservesLargeContextTarget',
    'TestContextBestFitBeatsResidentLongProfile',
    'TestStickyPlacementDoesNotSpillClientToLargerTarget',
    'TestTargetExecutionFingerprintCoversDispatchAndCapacityFacts',
    'TestAdmissionOwnedPlacementGenerationHandoff',
  ], 'manager regression inventory');
  verifyAdmissionOwnedHandoffSource(files);
  verifyMutantSeams(files);
  verifyDynamicComboCallsite(files.get('internal/workloads/comfy_discovery.go'));
  verifyTranscriptOracle();
  return { mode: 'source-only', files: owned.length, protocolInventory: protocolParents.length, placementInventory: placementParents.length, effects: 'none' };
}

function verifyAdmissionOwnedHandoffSource(files) {
  const manager = files.get('internal/workloads/manager.go');
  const tests = files.get('internal/workloads/manager_test.go');
  const helperStart = manager.indexOf('func (m *Manager) handoffAdmissionOwnedPlacementGeneration(');
  const helperEnd = manager.indexOf('\n// Release-state fields share placementMu', helperStart);
  if (helperStart < 0 || helperEnd < 0) throw new Error('missing bounded admission-owned handoff implementation');
  const helper = manager.slice(helperStart, helperEnd);
  for (const token of [
    'GetResidencyTransition(context.Background(), transitionID)',
    'GetAcceleratorLease(context.Background(), lease.AcceleratorID)',
    'GetResidencyTransitionByIdempotency(context.Background(), transition.IdempotencyKey)',
    'MaxResidencyFencingToken(context.Background(), transition.TargetID, transition.Model)',
    'transition.FencingToken < lease.FencingToken',
    'currentLease.ExpiresAt.After(time.Now())',
    'validateAuthoritativeTransitionEvidence',
    'transition.TargetGeneration != cursorGeneration',
    'transition.ExecutionFingerprint != targetExecutionFingerprint(cursor)',
    'transition.Reason == "capacity_for_demand runtime="+residencyCapacityIdentity(cursor)',
    'transition.Reason == "workload_demand runtime="+residencyCapacityIdentity(cursor)',
    'sameStringSet(cursor.ResidentModels, after.ResidentModels)',
    'm.admissionReservationReleasing(reservation)',
    'm.placementMu.Lock()',
  ]) if (!helper.includes(token)) throw new Error(`admission-owned transition proof omitted ${token}`);
  let managerLock = false;
  let placementLock = false;
  for (const line of helper.split('\n')) {
    if (line.includes('m.mu.RLock()') || line.includes('m.mu.Lock()')) managerLock = true;
    if (line.includes('m.placementMu.Lock()')) placementLock = true;
    if (managerLock && placementLock) throw new Error('admission handoff nests manager and placement locks');
    if (line.includes('m.mu.RUnlock()') || line.includes('m.mu.Unlock()')) managerLock = false;
    if (line.includes('m.placementMu.Unlock()')) placementLock = false;
  }
  const releaseStart = manager.indexOf('func (m *Manager) admissionReservationReleasing(');
  const releaseEnd = manager.indexOf('\nfunc withoutExact(', releaseStart);
  if (releaseStart < 0 || releaseEnd < 0) throw new Error('missing placementMu release-state snapshot');
  const releaseSnapshot = manager.slice(releaseStart, releaseEnd);
  if (!releaseSnapshot.includes('m.placementMu.Lock()') || !releaseSnapshot.includes('reservation.released') || !releaseSnapshot.includes('reservation.releaseRequested') || !releaseSnapshot.includes('reservation.releaseInFlight')) throw new Error('release-state snapshot omitted placementMu-owned lifecycle flags');
  for (const token of [
    'multi-victim replacement', 'legacy unprofiled context-zero load', 'foreign transition',
    'changed target device', 'changed target model', 'changed target capacity', 'changed target runtime',
    'unrelated target refresh', 'actual multiple-victim eviction and load', 'actual single-load legacy context-zero',
    'adapter.Counts()', 'ObservedTier != domain.ResidencyColdDisk',
    'allocated same-model highwater exceeds accelerator lease', 'AllocateResidencyTransition',
    'SetModelCapacity(ctx, measuredCapacity(registered, measuredModel, 1<<30))',
    'CapacityVerified: true, CapacitySource: "runtime:/slots"',
  ]) if (!tests.includes(token)) throw new Error(`admission-owned lifecycle regression omitted ${token}`);
}

function verifyDynamicComboCallsite(source) {
  const call = 'childRequired, childOptional, dynamic, selected := comfyDynamicChildInputsExact(spec, value)';
  const declaration = 'func comfyDynamicChildInputsExact(rawSpec, rawValue json.RawMessage) (map[string]json.RawMessage, map[string]json.RawMessage, bool, bool)';
  const shape = (text) => text.includes(call) && text.includes(declaration);
  if (!shape(source) || source.split(call).length !== 2 || source.split(declaration).length !== 2) throw new Error('DynamicCombo fixed-point call/declaration arity is not exact');
  const omitted = source.replace(call, 'childRequired, childOptional, dynamic, selected := comfyDynamicChildInputs(spec, value)');
  if (shape(omitted)) throw new Error('DynamicCombo helper-call omission control failed to detect the wrong helper');
}

function verifyTranscriptOracle() {
  const event = (Action, Test, extra = {}) => ({ Action, Package: 'fixture', ...(Test ? { Test } : {}), ...extra });
  const transcript = (fixture) => typeof fixture === 'string' ? fixture : fixture.map((item) => JSON.stringify(item)).join('\n');
  const positive = [event('start'), event('run', 'TestParent'), event('run', 'TestParent/child'), event('output', 'TestParent/child', { Output: '=== RUN child\n' }), event('pass', 'TestParent/child', {Elapsed:0.001}), event('pass', 'TestParent', {Elapsed:0.001}), event('output', undefined, { Output: 'PASS\n' }), event('output', undefined, { Output: 'ok  fixture\t0.001s\n' }), event('pass', undefined, {Elapsed:0.001})];
  parseGoJSON(positive.map((item) => JSON.stringify(item)).join('\n'), ['TestParent'], 'fixture');
  const unequalSuccessClocks = positive.map((item) => item.Action === 'pass' && item.Test === undefined ? { ...item, Elapsed:0.009 } : item);
  parseGoJSON(unequalSuccessClocks.map((item) => JSON.stringify(item)).join('\n'), ['TestParent'], 'fixture');
  const withTerminalElapsed = (events, value) => events.map((item) => item.Action === 'pass' && item.Test === undefined ? { ...item, Elapsed:value } : item);
  const withoutTerminalElapsed = positive.map((item) => {
    if (item.Action !== 'pass' || item.Test !== undefined) return item;
    const {Elapsed, ...rest} = item;
    return rest;
  });
  const nonfiniteTerminalElapsed = positive.map((item) => item.Action === 'pass' && item.Test === undefined
    ? '{"Action":"pass","Package":"fixture","Elapsed":1e400}'
    : JSON.stringify(item)).join('\n');
  const negatives = [
    [event('start'), event('run', 'TestParent'), event('pass', 'TestParent'), event('pass')],
    [...positive, event('pass', 'TestParent')],
    [event('start'), event('run', 'TestParent'), event('run', 'TestParent/child'), event('skip', 'TestParent/child'), event('pass', 'TestParent'), event('pass')],
    [event('start'), event('run', 'TestParent'), event('run', 'Foreign'), event('pass', 'Foreign'), event('pass', 'TestParent'), event('pass')],
    [event('start'), event('run', 'TestParent'), event('fail', 'TestParent'), event('pass')],
    [event('start'), event('run', 'TestParent'), event('run', 'TestParent/child'), event('run', 'TestParent/child'), event('pass', 'TestParent/child'), event('pass', 'TestParent'), event('pass')],
    [event('start'), event('run', 'TestParent'), event('pass', 'TestParent'), event('run', 'TestParent/child'), event('pass', 'TestParent/child'), event('pass')],
    [event('start'), event('run', 'TestSecond'), event('pass', 'TestSecond'), event('run', 'TestParent'), event('pass', 'TestParent'), event('pass')],
    [event('start'), event('run', 'TestParent'), event('pass', 'TestParent'), event('fail')],
    [event('run', 'TestParent'), event('pass', 'TestParent'), event('pass')],
    positive.map((item) => item.Action === 'output' && item.Output?.startsWith('ok') ? { ...item, Output: 'ok  foreign/pkg\t0.001s\n' } : item),
    positive.map((item) => item.Action === 'output' && item.Output?.startsWith('ok') ? { ...item, Output: 'ok  fixture\t(cached)\n' } : item),
    positive.map((item) => item.Action === 'output' && item.Output?.startsWith('ok') ? { ...item, Output: 'ok  fixture\tnot-a-duration\n' } : item),
    positive.map((item) => item.Action === 'output' && item.Output?.startsWith('ok') ? { ...item, Output: 'ok  fixture\t120.001s\n' } : item),
    positive.map((item,index) => item.Action === 'output' && item.Output === 'PASS\n' ? { ...item, Output: 'PASS\n' } : item).flatMap((item) => item.Output === 'ok  fixture\t0.001s\n' ? [item,item] : [item]),
    [...positive.slice(0,6), positive[7], positive[6], ...positive.slice(8)],
    positive.map((item) => item.Action === 'run' && item.Test === 'TestParent' ? { ...item, Action: 'pause' } : item),
    withoutTerminalElapsed,
    withTerminalElapsed(positive, null),
    nonfiniteTerminalElapsed,
    withTerminalElapsed(positive, -0.001),
    withTerminalElapsed(positive, 120.001),
    positive.map((item) => item.Action === 'output' && item.Output?.startsWith('ok') ? { ...item, Package:'foreign/pkg' } : item),
  ];
  for (const fixture of negatives) {
    let rejected = false;
    try { parseGoJSON(transcript(fixture), ['TestParent'], 'fixture'); } catch { rejected = true; }
    if (!rejected) throw new Error('transcript negative control was accepted');
  }
  const mutantFailure = [
    event('start'), event('run', 'TestParent'),
    event('output', 'TestParent', { Output: '    discovery rejected: wanted marker\n' }),
    event('fail', 'TestParent', {Elapsed:0.002}), event('output', undefined, { Output: 'FAIL\n' }), event('output', undefined, { Output: 'FAIL\tfixture\t0.002s\n' }), event('fail', undefined, {Elapsed:0.009}),
  ];
  assertExpectedMutantFailure(mutantFailure.map((item) => JSON.stringify(item)).join('\n'), 'TestParent', 'wanted marker', 'fixture', 'TestParent', 'top-level-control');
  for (const fixture of [
    [event('run'), event('run', 'TestParent'), event('fail', 'TestParent'), event('output', undefined, { Output: 'FAIL\n' }), event('output', undefined, { Output: 'FAIL\tfixture\t0.002s\n' }), event('fail')],
    [event('start'), event('run', 'TestParent'), event('output', 'TestParent', { Output: 'wanted marker\n' }), event('fail', 'TestParent'), event('output', undefined, { Output: 'FAIL\n' }), event('fail')],
    [...mutantFailure, event('output', undefined, { Output: 'late output\n' })],
    mutantFailure.map((item) => item.Action === 'output' && item.Output?.startsWith('FAIL\t') ? { ...item, Output:'FAIL\tforeign/pkg\t0.002s\n' } : item),
    mutantFailure.map((item) => item.Action === 'output' && item.Output?.startsWith('FAIL\t') ? { ...item, Output:'FAIL\tfixture\t(cached)\n' } : item),
    mutantFailure.map((item) => item.Action === 'output' && item.Output?.startsWith('FAIL\t') ? { ...item, Output:'FAIL\tfixture\tnot-a-duration\n' } : item),
    mutantFailure.map((item) => item.Action === 'output' && item.Output?.startsWith('FAIL\t') ? { ...item, Output:'FAIL\tfixture\t120.001s\n' } : item),
    mutantFailure.map((item) => item.Action === 'fail' && item.Test === undefined ? {...item,Elapsed:undefined} : item),
    mutantFailure.map((item) => item.Action === 'fail' && item.Test === undefined ? {...item,Elapsed:null} : item),
    mutantFailure.map((item) => item.Action === 'fail' && item.Test === undefined ? {...item,Elapsed:-0.001} : item),
    mutantFailure.map((item) => item.Action === 'fail' && item.Test === undefined ? {...item,Elapsed:120.001} : item),
    mutantFailure.map((item) => item.Action === 'fail' && item.Test === undefined
      ? '{"Action":"fail","Package":"fixture","Elapsed":1e400}'
      : JSON.stringify(item)).join('\n'),
    mutantFailure.flatMap((item) => item.Action === 'output' && item.Output?.startsWith('FAIL\t') ? [item,item] : [item]),
  ]) {
    let rejected = false;
    try { assertExpectedMutantFailure(transcript(fixture), 'TestParent', 'wanted marker', 'fixture', 'TestParent', 'legacy-negative-control'); } catch { rejected = true; }
    if (!rejected) throw new Error('mutant transcript negative control was accepted');
  }
  const nestedMutantFailure = [
    event('start'), event('run', 'TestParent'),
    event('run', 'TestParent/sibling'), event('output', 'TestParent/sibling', { Output: 'sibling completed\n' }), event('pass', 'TestParent/sibling', {Elapsed:0.001}),
    event('run', 'TestParent/child'), event('output', 'TestParent/child', { Output: 'wanted nested marker\n' }), event('fail', 'TestParent/child', {Elapsed:0.002}),
    event('fail', 'TestParent', {Elapsed:0.002}), event('output', undefined, { Output: 'FAIL\n' }), event('output', undefined, { Output: 'FAIL\tfixture\t0.002s\n' }), event('fail', undefined, {Elapsed:0.009}),
  ];
  const nestedText = (events) => events.map((item) => JSON.stringify(item)).join('\n');
  assertExpectedMutantFailure(nestedText(nestedMutantFailure), 'TestParent', 'wanted nested marker', 'fixture', 'TestParent/child', 'nested-owner-positive-control');
  // The package terminal and textual test summary use independent Go clocks.
  // A differing, individually bounded elapsed value is a valid transcript.
  const nestedUnequalClocks = nestedMutantFailure.map((item) => item.Test === undefined && item.Action === 'fail'
    ? {...item,Elapsed:0.011}
    : item);
  assertExpectedMutantFailure(nestedText(nestedUnequalClocks), 'TestParent', 'wanted nested marker', 'fixture', 'TestParent/child', 'nested-owner-unequal-clock-positive-control');
  const wrongMarkerOwner = nestedMutantFailure.map((item) => {
    if (item.Action === 'output' && item.Test === 'TestParent/child') return {...item,Output:'child failure without marker\n'};
    if (item.Action === 'fail' && item.Test === 'TestParent') return {...item,Output:undefined};
    return item;
  });
  wrongMarkerOwner.splice(wrongMarkerOwner.findIndex((item) => item.Action === 'fail' && item.Test === 'TestParent'), 0, event('output','TestParent',{Output:'wanted nested marker\n'}));
  const extraFailingSibling = [...nestedMutantFailure];
  extraFailingSibling.splice(extraFailingSibling.findIndex((item) => item.Action === 'run' && item.Test === 'TestParent/child'), 0,
    event('run','TestParent/unrelated'), event('fail','TestParent/unrelated',{Elapsed:0.001}));
  const skippedSibling = [...nestedMutantFailure];
  skippedSibling.splice(skippedSibling.findIndex((item) => item.Action === 'run' && item.Test === 'TestParent/child'), 0,
    event('run','TestParent/skipped'), event('skip','TestParent/skipped',{Elapsed:0}));
  const missingExpectedChild = nestedMutantFailure.filter((item) => item.Test !== 'TestParent/child');
  const incompleteExpectedChild = nestedMutantFailure.filter((item) => !(item.Action === 'fail' && item.Test === 'TestParent/child'));
  for (const [fixture, owner, marker] of [
    [nestedMutantFailure, 'TestParent', 'wanted nested marker'],
    [wrongMarkerOwner, 'TestParent/child', 'wanted nested marker'],
    [extraFailingSibling, 'TestParent/child', 'wanted nested marker'],
    [skippedSibling, 'TestParent/child', 'wanted nested marker'],
    [missingExpectedChild, 'TestParent/child', 'wanted nested marker'],
    [incompleteExpectedChild, 'TestParent/child', 'wanted nested marker'],
    [nestedMutantFailure, 'TestParent/not-the-child', 'wanted nested marker'],
  ]) {
    let rejected = false;
    try { assertExpectedMutantFailure(nestedText(fixture), 'TestParent', marker, 'fixture', owner, 'nested-negative-control'); } catch (error) { rejected = error.message.includes('nested-negative-control'); }
    if (!rejected) throw new Error('nested mutant transcript negative control was accepted or lacked its label');
  }
  let malformedRejected = false;
  try { parseGoJSON('{broken', ['TestParent'], 'fixture'); } catch { malformedRejected = true; }
  if (!malformedRejected) throw new Error('malformed transcript negative control was accepted');
  assertProcessResult({ status: 0, signal: null, error: null }, 0, 'positive process fixture');
  for (const fixture of [
    { status: null, signal: null, error: null },
    { status: 1, signal: null, error: null },
    { status: 0, signal: 'SIGTERM', error: null },
    { status: 0, signal: null, error: new Error('spawn failed') },
  ]) {
    let rejected = false;
    try { assertProcessResult(fixture, 0, 'negative process fixture'); } catch { rejected = true; }
    if (!rejected) throw new Error('null/nonzero/signal/error child result was accepted');
  }
}

function assertOrderedSubsequence(actual, expected, label) {
  let cursor = -1;
  for (const name of expected) {
    const index = actual.indexOf(name);
    if (index <= cursor) throw new Error(`${label} is missing or out of declaration order at ${name}`);
    cursor = index;
  }
}

// go test's textual summary and test2json's terminal Elapsed use independent clocks.
// Validate the summary here; the JSON terminal duration is independently bounded by each parser.
function parsePackageSummary(output, expectedPackage, result) {
  if (typeof output !== 'string') return null;
  const escaped = expectedPackage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const prefix = result === 'pass' ? 'ok' : 'FAIL';
  const match = output.match(new RegExp(`^${prefix}[\\t ]+${escaped}[\\t ]+(\\d+(?:\\.\\d+)?)s\\n$`));
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) && seconds >= 0 && seconds <= 120 ? seconds : null;
}

function parseGoJSON(output, expected, expectedPackage = 'fixture') {
  const events = [];
  const observedParents = [];
  let packageStarted = false;
  let packageState = '';
  let packagePassOutput = false;
  let packageSummary = null;
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error('malformed Go test JSON transcript'); }
    if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.Action !== 'string' || event.Package !== expectedPackage) throw new Error('malformed or foreign Go test event');
    if (Object.keys(event).some((key) => !['Action','Package','Test','Output','Elapsed','Time'].includes(key))) throw new Error('Go event contains an unsupported field');
    if (event.Time !== undefined && typeof event.Time !== 'string') throw new Error('malformed Go event time');
    if (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0 || event.Elapsed > 120)) throw new Error('malformed Go event elapsed time');
    events.push(event);
  }
  const state = new Map();
  for (let index = 0; index < events.length; index++) {
    const event = events[index];
    if (event.Action === 'output' ? typeof event.Output !== 'string' : event.Output !== undefined) throw new Error('Go event has an invalid Output field shape');
    if (event.Test === undefined) {
      if (event.Action === 'start') {
        if (packageStarted || index !== 0 || event.Output !== undefined || event.Elapsed !== undefined) throw new Error('duplicate, late, or malformed package start');
        packageStarted = true;
        packageState = 'running';
      } else if (event.Action === 'output') {
        if (packageState !== 'running' || typeof event.Output !== 'string' || expected.some((name) => state.get(name) !== 'pass')) throw new Error('package output was malformed or preceded completed exact tests');
        if (event.Output === 'PASS\n') { if (packagePassOutput || packageSummary !== null) throw new Error('duplicate or late package PASS output'); packagePassOutput = true; }
        else {
          const seconds = parsePackageSummary(event.Output, expectedPackage, 'pass');
          if (!packagePassOutput || packageSummary !== null || seconds === null) throw new Error('package summary was early, duplicate, malformed, foreign, cached, or out of bounds');
          packageSummary = seconds;
        }
      } else if (['pass', 'fail', 'skip'].includes(event.Action)) {
        if (packageState !== 'running' || event.Output !== undefined) throw new Error('package terminal without unique start or with invalid output');
        if (expected.some((name) => state.get(name) !== event.Action)) throw new Error('package terminal preceded an exact top-level result');
        if (event.Action !== 'pass' || !packagePassOutput || packageSummary === null || event.Elapsed === undefined) throw new Error('package PASS lacked exact PASS and independently bounded summary/terminal durations');
        packageState = event.Action;
      } else {
        throw new Error(`unexpected package test action ${event.Action}`);
      }
      continue;
    }
    if (packageState !== 'running') throw new Error('test event occurred outside the package run');
    if (typeof event.Test !== 'string' || event.Test.length === 0) throw new Error('malformed test name');
    const name = event.Test;
    const parent = name.split('/')[0];
    if (!expected.includes(parent)) throw new Error(`foreign Go test result ${name}`);
    if (event.Action === 'run') {
      if (state.has(name)) throw new Error(`duplicate test start ${name}`);
      const immediateParent = name.includes('/') ? name.slice(0, name.lastIndexOf('/')) : '';
      if (immediateParent && state.get(immediateParent) !== 'running') throw new Error(`nested test began without active parent ${name}`);
      state.set(name, 'running');
      if (!name.includes('/')) observedParents.push(name);
    } else if (['pass', 'fail', 'skip'].includes(event.Action)) {
      if (!state.has(name) || state.get(name) !== 'running') throw new Error(`terminal event without unique run for ${name}`);
      if ([...state].some(([child, result]) => child.startsWith(name + '/') && result === 'running')) throw new Error(`parent terminated before nested result ${name}`);
      state.set(name, event.Action);
    } else if (event.Action === 'output') {
      if (!state.has(name) || state.get(name) !== 'running' || typeof event.Output !== 'string') throw new Error('malformed or out-of-order Go output event');
    } else {
      throw new Error(`unexpected Go test action ${event.Action}`);
    }
  }
  if (observedParents.length !== expected.length || observedParents.some((name, index) => name !== expected[index])) throw new Error('Go test inventory was missing, foreign, or out of order');
  for (const name of expected) if (state.get(name) !== 'pass') throw new Error(`expected exact PASS for ${name}; got ${state.get(name) ?? 'missing'}`);
  for (const [name, result] of state) {
    const parent = name.split('/')[0];
    if (!expected.includes(parent)) throw new Error(`foreign Go test result ${name}`);
    if (result !== 'pass') throw new Error(`non-PASS Go test result ${name}: ${result}`);
  }
  if (!packageStarted || packageState !== 'pass') throw new Error(`expected exact package PASS; got ${packageState || 'missing'}`);
  return events;
}

function assertProcessResult(result, expectedStatus, label) {
  if (!result || result.error || result.signal || typeof result.status !== 'number' || result.status !== expectedStatus) {
    throw new Error(`${label} did not return exact status ${expectedStatus} (status=${result?.status ?? 'null'}, signal=${result?.signal ?? ''}, error=${result?.error?.message ?? ''})`);
  }
}

async function runInventory(packagePath, names) {
  const { spawnSync } = await import('node:child_process');
  const pattern = `^(${names.join('|')})$`;
  const result = spawnSync('go', ['test', '-json', packagePath, '-run', pattern, '-count=1'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 120000,
    maxBuffer: 16 << 20,
    windowsHide: true,
  });
  assertProcessResult(result, 0, 'Go inventory');
  parseGoJSON(result.stdout, names, expectedGoPackage(packagePath));
}

function replaceUnique(source, needle, replacement, label) {
  const first = source.indexOf(needle);
  if (first < 0 || source.indexOf(needle, first + needle.length) >= 0) throw new Error(`mutant seam is absent or ambiguous: ${label}`);
  return source.slice(0, first) + replacement + source.slice(first + needle.length);
}

function assertExpectedMutantFailure(stdout, expectedTest, marker, expectedPackage, assertionOwnerPath = expectedTest, label = 'mutant') {
  try {
    parseExpectedMutantFailure(stdout, expectedTest, marker, expectedPackage, assertionOwnerPath);
  } catch (error) {
    throw new Error(`${label} mutant transcript: ${error.message}`);
  }
}

function parseExpectedMutantFailure(stdout, expectedTest, marker, expectedPackage, assertionOwnerPath) {
  const events = [];
  for (const line of stdout.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error('mutant produced malformed Go test transcript'); }
    if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.Action !== 'string' || event.Package !== expectedPackage) throw new Error('mutant produced malformed or foreign Go test event');
    if (Object.keys(event).some((key) => !['Action','Package','Test','Output','Elapsed','Time'].includes(key))) throw new Error('mutant Go event contains unsupported fields');
    if (event.Time !== undefined && typeof event.Time !== 'string') throw new Error('mutant Go event time is malformed');
    if (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0 || event.Elapsed > 120)) throw new Error('mutant Go elapsed time is malformed');
    events.push(event);
  }
  if (!events.length) throw new Error('mutant produced no Go test events');
  if (events.some((event) => event.Action === 'output' ? typeof event.Output !== 'string' : event.Output !== undefined)) throw new Error('mutant Go event has an invalid Output field shape');
  const packageEvents = events.filter((event) => event.Test === undefined);
  if (packageEvents.filter((event) => event.Action === 'start').length !== 1 || packageEvents.filter((event) => event.Action === 'fail').length !== 1 || packageEvents.some((event) => event.Action === 'pass' || event.Action === 'skip')) {
    throw new Error('mutant lacks exact package start/fail terminal state');
  }
  if (events[0].Action !== 'start' || events[0].Test !== undefined || events[0].Output !== undefined || events[0].Elapsed !== undefined || events.at(-1).Test !== undefined || events.at(-1).Action !== 'fail') throw new Error('mutant package start or terminal order is invalid');
  const packageFailIndex = events.findIndex((event) => event.Test === undefined && event.Action === 'fail');
  const packageStartIndex = events.findIndex((event) => event.Test === undefined && event.Action === 'start');
  if (events.some((event, index) => event.Test !== undefined && (index < packageStartIndex || index > packageFailIndex))) {
    throw new Error('mutant test results occurred outside package start/fail boundaries');
  }
  const states = new Map();
  const output = new Map();
  const observedParents = [];
  let sawStandaloneFail = false;
  let failureSummary = null;
  let packageFailed = false;
  for (const event of events) {
    if (event.Test === undefined) {
      if (event.Action === 'start') continue;
      if (event.Action === 'output') {
        if (typeof event.Output !== 'string' || [...states.values()].some((state) => state === 'running')) throw new Error('mutant package output is malformed or premature');
        if (event.Output === 'FAIL\n') { if (sawStandaloneFail || failureSummary !== null) throw new Error('duplicate or late standalone FAIL output'); sawStandaloneFail = true; }
        else {
          const seconds = parsePackageSummary(event.Output, expectedPackage, 'fail');
          if (!sawStandaloneFail || failureSummary !== null || seconds === null) throw new Error('mutant final FAIL summary was malformed, duplicate, foreign, cached, or out of order');
          failureSummary = seconds;
        }
        continue;
      }
      if (event.Action === 'fail') {
        if (packageFailed || !sawStandaloneFail || failureSummary === null || event.Elapsed === undefined || event !== events.at(-1)) throw new Error('mutant package failure terminal lacked independently bounded summary/terminal durations or was not final');
        packageFailed = true;
        continue;
      }
      throw new Error(`unexpected mutant package action ${event.Action}`);
    }
    if (sawStandaloneFail || failureSummary !== null) throw new Error('mutant test event occurred after package failure output began');
    if (typeof event.Test !== 'string' || !event.Test) throw new Error('malformed mutant test name');
    if (event.Test !== expectedTest && !event.Test.startsWith(`${expectedTest}/`)) throw new Error(`mutant produced foreign test ${event.Test}`);
    if (event.Action === 'run') {
      if (states.has(event.Test)) throw new Error(`duplicate mutant test start ${event.Test}`);
      const immediateParent = event.Test.includes('/') ? event.Test.slice(0,event.Test.lastIndexOf('/')) : '';
      if (immediateParent && states.get(immediateParent) !== 'running') throw new Error('mutant child started without intended parent');
      states.set(event.Test, 'running');
      if (!event.Test.includes('/')) observedParents.push(event.Test);
    } else if (event.Action === 'output') {
      if (states.get(event.Test) !== 'running' || typeof event.Output !== 'string' || event.Output === 'FAIL\n' || parsePackageSummary(event.Output, expectedPackage, 'fail') !== null || parsePackageSummary(event.Output, expectedPackage, 'pass') !== null) throw new Error('malformed, out-of-order, or package-owned mutant test output');
      output.set(event.Test, `${output.get(event.Test) ?? ''}${event.Output}`);
    } else if (['pass', 'fail', 'skip'].includes(event.Action)) {
      if (states.get(event.Test) !== 'running') throw new Error(`mutant terminal without unique run ${event.Test}`);
      if ([...states].some(([name, state]) => name.startsWith(`${event.Test}/`) && state === 'running')) throw new Error('parent terminated before nested tests settled');
      states.set(event.Test, event.Action);
    } else {
      throw new Error(`unexpected mutant test action ${event.Action}`);
    }
  }
  const ownerParts = assertionOwnerPath.split('/');
  if (ownerParts[0] !== expectedTest || ownerParts.some((part) => !/^[A-Za-z0-9_]+$/.test(part))) throw new Error('mutant assertion owner is not an exact path beneath the expected parent');
  const ownerAncestors = ownerParts.map((_, index) => ownerParts.slice(0, ownerParts.length - index).join('/'));
  if (ownerParts.length === 0 || states.get(assertionOwnerPath) !== 'fail') throw new Error(`mutant did not fail at the exact intended assertion owner ${assertionOwnerPath}`);
  if (!packageFailed) throw new Error('mutant lacked exact final package failure');
  const failures = [...states].filter(([, state]) => state === 'fail').map(([name]) => name).sort();
  const expectedFailures = [...ownerAncestors].sort();
  if (failures.length !== expectedFailures.length || failures.some((name, index) => name !== expectedFailures[index])) throw new Error(`mutant failed outside the exact assertion-owner ancestry: ${failures.join(',')}`);
  if (observedParents.length !== 1 || observedParents[0] !== expectedTest) throw new Error('mutant parent inventory was not exactly the expected top-level test');
  for (const [name, state] of states) {
    if (ownerAncestors.includes(name)) { if (state !== 'fail') throw new Error(`mutant assertion-owner ancestor did not fail: ${name}`); }
    else if (state !== 'pass') throw new Error(`mutant produced skipped/incomplete/extra failing test ${name}`);
  }
  for (const [name, text] of output) {
    const ownsMarker = name === assertionOwnerPath;
    if (text.includes(marker) !== ownsMarker) throw new Error(`mutant assertion marker ownership mismatch at ${name}`);
  }
  if (!(output.get(assertionOwnerPath) ?? '').includes(marker)) throw new Error(`mutant assertion owner omitted intended marker ${marker}`);
}

async function runMutant(files, relativePath, needle, replacement, packagePath, testName, marker, label, assertionOwnerPath = testName) {
  const fsPromises = fs;
  const os = await import('node:os');
  const { spawnSync } = await import('node:child_process');
  const directory = fsPromises.mkdtempSync(path.join(os.tmpdir(), 'comfy-fleet-discovery-'));
  const sourcePath = path.resolve(root, relativePath);
  const overlaySource = path.join(directory, 'mutant.go');
  const overlayPath = path.join(directory, 'overlay.json');
  try {
    const original = files.get(relativePath);
    if (original === undefined) throw new Error(`mutant source was not in read snapshot: ${relativePath}`);
    const mutated = Array.isArray(needle)
      ? needle.reduce((source, [stepNeedle, stepReplacement], index) => replaceUnique(source, stepNeedle, stepReplacement, `${label} step ${index + 1}`), original)
      : replaceUnique(original, needle, replacement, label);
    const overlayJSON = JSON.stringify({ Replace: { [sourcePath]: overlaySource } });
    if (Buffer.byteLength(mutated, 'utf8') > maxSourceBytes || Buffer.byteLength(overlayJSON, 'utf8') > 4096) throw new Error(`${label} overlay exceeds its byte bound`);
    fsPromises.writeFileSync(overlaySource, mutated, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    fsPromises.writeFileSync(overlayPath, overlayJSON, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    const result = spawnSync('go', ['test', '-json', `-overlay=${overlayPath}`, packagePath, '-run', `^(${testName})$`, '-count=1'], {
      cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 16 << 20, windowsHide: true,
    });
    assertProcessResult(result, 1, `${label} mutant`);
    assertExpectedMutantFailure(result.stdout, testName, marker, expectedGoPackage(packagePath), assertionOwnerPath, label);
  } finally {
    const names = fsPromises.readdirSync(directory).sort();
    const allowed = ['mutant.go', 'overlay.json'];
    if (names.some((name) => !allowed.includes(name))) throw new Error(`${label} overlay directory contains unexpected entries`);
    for (const name of names) {
      const exact = path.join(directory, name);
      const stat = fsPromises.lstatSync(exact);
      if (!stat.isFile() || stat.isSymbolicLink()) throw new Error(`${label} overlay file is not a regular file`);
      fsPromises.unlinkSync(exact);
    }
    if (fsPromises.readdirSync(directory).length !== 0) throw new Error(`${label} overlay directory is not empty after exact cleanup`);
    fsPromises.rmdirSync(directory);
  }
}

function verifyMutantSeams(files) {
  const cases = [
    ['internal/api/comfy_discovery_http.go', 'p, ok := s.requirePrincipal(w, r, "comfy:read")', 'p, ok := Principal{EgressPolicy: "local_only", Adapters: map[string]struct{}{"comfy": {}}}, true', 'authorization bypass'],
    ['internal/workloads/comfy_discovery.go', 'return http.ErrUseLastResponse', 'return nil', 'redirect follow'],
    ['internal/workloads/comfy_discovery.go', 'req.Header.Set("Authorization", source.Target.Authorization)', 'req.Header.Del("Authorization")', 'backend credential omission'],
    ['internal/workloads/comfy_discovery.go', [
      ['if source.Target.Authorization != "" {', 'if source.Target.Authorization != "" || true {'],
      ['req.Header.Set("Authorization", source.Target.Authorization)', 'req.Header.Set("Authorization", "Bearer comfy-reader-token")'],
    ], '', 'caller credential forwarding'],
    ['internal/workloads/comfy_discovery.go', 'if err := validateComfyRequestSchema(request, schema); err != nil { return comfySchemaProof{}, err }', 'if false { return comfySchemaProof{}, errComfyDiscoveryUnavailable }', 'graph validation bypass'],
    ['internal/workloads/comfy_discovery.go', 'target.Adapter != "comfy" || !target.Enabled || target.Quarantined', 'target.Adapter != "comfy" || target.Quarantined', 'disabled target admission'],
    ['internal/workloads/manager.go', 'if schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof) {', 'if (schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof)) && false {', 'production stale schema fence'],
    ['internal/workloads/manager.go', 'handoffErr := m.handoffAdmissionOwnedPlacementGeneration(reservation, beforeLoadTarget, target, beforeLoadGeneration, afterLoadGeneration, req.Model, w.Request.OwnerID, w.Request.IdempotencyKey, transitionIDs, beforeLoadPlacement)', 'handoffErr := error(nil)\n\t\t\t\t_ = beforeLoadGeneration\n\t\t\t\t_ = beforeLoadPlacement', 'admission-owned placement generation handoff'],
  ];
  for (const [pathName, needle, replacement, label] of cases) {
    const original = files.get(pathName);
    if (original === undefined) throw new Error(`missing mutant source ${pathName}`);
    if (Array.isArray(needle)) needle.reduce((source, [a, b], index) => replaceUnique(source, a, b, `${label} step ${index + 1}`), original);
    else replaceUnique(original, needle, replacement, label);
  }
  const staleSchemaMutation = replaceUnique(
    files.get('internal/workloads/manager.go'),
    'if schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof) {',
    'if (schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof)) && false {',
    'compile-safe stale schema fence bypass');
  if (!staleSchemaMutation.includes('schemaErr != nil') || !staleSchemaMutation.includes('comfySchemaProofMatches(reservation.comfySchemaProof, latestProof)) && false {')) {
    throw new Error('stale-schema mutant must keep both original observation variables used while bypassing the guard');
  }
  const handoffMutation = replaceUnique(
    files.get('internal/workloads/manager.go'),
    'handoffErr := m.handoffAdmissionOwnedPlacementGeneration(reservation, beforeLoadTarget, target, beforeLoadGeneration, afterLoadGeneration, req.Model, w.Request.OwnerID, w.Request.IdempotencyKey, transitionIDs, beforeLoadPlacement)',
    'handoffErr := error(nil)\n\t\t\t\t_ = beforeLoadGeneration\n\t\t\t\t_ = beforeLoadPlacement',
    'compile-safe admission-owned handoff bypass');
  if (!handoffMutation.includes('_ = beforeLoadGeneration') || !handoffMutation.includes('_ = beforeLoadPlacement') || handoffMutation.includes('handoffAdmissionOwnedPlacementGeneration(reservation, beforeLoadTarget')) {
    throw new Error('handoff mutant must compile while bypassing the exact handoff call');
  }
}

async function runControls(mode, files) {
  if (mode === '--mode=protocol') {
    await runMutant(files, 'internal/api/comfy_discovery_http.go',
      'p, ok := s.requirePrincipal(w, r, "comfy:read")',
      'p, ok := Principal{EgressPolicy: "local_only", Adapters: map[string]struct{}{"comfy": {}}}, true',
      './internal/api', 'TestComfyFleetDiscoveryAuthorization', 'status=200 want=401', 'authorization-bypass');
    await runMutant(files, 'internal/workloads/comfy_discovery.go',
      'return http.ErrUseLastResponse', 'return nil',
      './internal/workloads', 'TestComfyFleetDiscoveryTransportBounds', 'redirect was followed or accepted', 'redirect-follow');
    await runMutant(files, 'internal/workloads/comfy_discovery.go',
      'req.Header.Set("Authorization", source.Target.Authorization)',
      'req.Header.Del("Authorization")',
      './internal/api', 'TestComfyFleetDiscoveryFixedRoutes', 'backend credential isolation failed', 'credential-forwarding');
    await runMutant(files, 'internal/workloads/comfy_discovery.go',
      [
        ['if source.Target.Authorization != "" {', 'if source.Target.Authorization != "" || true {'],
        ['req.Header.Set("Authorization", source.Target.Authorization)', 'req.Header.Set("Authorization", "Bearer comfy-reader-token")'],
      ],
      '',
      './internal/api', 'TestComfyFleetDiscoveryFixedRoutes', 'caller credential reached uncredentialed backend', 'caller-credential-forwarding', 'TestComfyFleetDiscoveryFixedRoutes/caller_credential_is_not_forwarded_to_an_uncredentialed_route');
    return;
  }
  await runMutant(files, 'internal/workloads/comfy_discovery.go',
    'if err := validateComfyRequestSchema(request, schema); err != nil { return comfySchemaProof{}, err }',
    'if false { return comfySchemaProof{}, errComfyDiscoveryUnavailable }',
    './internal/workloads', 'TestComfyFleetGraphAdmissionRejectsCrossMachineGraphWithoutPost', 'unsatisfiable graph was POSTed', 'graph-validation-bypass');
  await runMutant(files, 'internal/workloads/comfy_discovery.go',
    'target.Adapter != "comfy" || !target.Enabled || target.Quarantined',
    'target.Adapter != "comfy" || target.Quarantined',
    './internal/workloads', 'TestComfyFleetDiscoveryEligibility', 'unexpected eligible snapshot', 'disabled-target');
  await runMutant(files, 'internal/workloads/manager.go',
    'if schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof) {', 'if (schemaErr != nil || !comfySchemaProofMatches(reservation.comfySchemaProof, latestProof)) && false {',
    './internal/workloads', 'TestComfyFleetGraphPreStartSchemaFence', 'schema changed without advertisement but backend received', 'stale-schema-proof');
  await runMutant(files, 'internal/workloads/manager.go',
    'handoffErr := m.handoffAdmissionOwnedPlacementGeneration(reservation, beforeLoadTarget, target, beforeLoadGeneration, afterLoadGeneration, req.Model, w.Request.OwnerID, w.Request.IdempotencyKey, transitionIDs, beforeLoadPlacement)',
    'handoffErr := error(nil)\n\t\t\t\t_ = beforeLoadGeneration\n\t\t\t\t_ = beforeLoadPlacement',
    './internal/workloads', 'TestContextBestFitBeatsResidentLongProfile', 'resident long-context route stole a short request', 'owned-placement-generation-handoff');
}

async function main() {
  if (mode === '--mode=source-only') {
    console.log(JSON.stringify(sourceOnly()));
    console.log('public Comfy fleet discovery source controls passed');
    return;
  }
  if (mode !== '--mode=protocol' && mode !== '--mode=placement') throw new Error('usage: verify-comfy-fleet-discovery.mjs --mode=source-only|protocol|placement');
  const files = readOwned();
  if (mode === '--mode=protocol') {
    exactInventory(files, 'internal/api/comfy_discovery_http_test.go', protocolParents.slice(0, 4));
    await runInventory('./internal/api', protocolParents);
    await runControls(mode, files);
    console.log('public Comfy fleet discovery protocol verification passed');
    console.log(JSON.stringify({ mode: 'protocol', result: 'PASS', tests: protocolParents }));
    return;
  }
  exactInventory(files, 'internal/workloads/comfy_discovery_test.go', placementParents.slice(0, 10));
  await runInventory('./internal/workloads', placementParents);
  await runControls(mode, files);
  console.log('public Comfy fleet placement verification passed');
  console.log(JSON.stringify({ mode: 'placement', result: 'PASS', tests: placementParents }));
}

main().catch((error) => {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
});
