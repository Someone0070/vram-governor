import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2];
const maxBytes = 2 << 20;
const sourcePath = 'internal/api/workloads_http.go';
const testPath = 'internal/api/comfy_history_http_test.go';
const tests = [
  'TestComfyHistorySingleGraphNativeShape',
  'TestComfyHistoryManagedExecutionIdentity',
  'TestComfyHistoryMultiChunkPreservation',
  'TestComfyHistoryAuthorizationAndOwners',
  'TestComfyHistoryInvalidAndStoreFailures',
  'TestComfyHistoryArtifactViewContinuity',
];
const regressions = [
  'TestComfyFleetDiscoveryAuthorization',
  'TestComfyFleetDiscoveryFixedRoutes',
  'TestWorkloadAuthPriorityClampAndOwnership',
];
const workloadRegressions = ['TestComfyPromptMappingTracksTargetAndBackendWithoutOverwriteRace'];
const singleHistoryRecordLoop = '\t\tfor _, record := range backend {\n\t\t\tnormalized = append([]byte(nil), record...)\n\t\t}';
const nestedSingleHistoryRecordLoop = '\t\tfor backendID, record := range backend {\n\t\t\tnormalized, _ = json.Marshal(map[string]json.RawMessage{backendID: record})\n\t\t}';

function readBounded(relative) {
  const absolute = path.resolve(root, relative);
  if (!absolute.startsWith(root + path.sep)) throw new Error(`unsafe path: ${relative}`);
  const stat = fs.lstatSync(absolute);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes) throw new Error(`unbounded or non-regular file: ${relative}`);
  const fd = fs.openSync(absolute, 'r');
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || opened.size !== stat.size || opened.size > maxBytes || opened.dev !== stat.dev || opened.ino !== stat.ino) throw new Error(`file changed before read: ${relative}`);
    const buffer = Buffer.alloc(stat.size + 1);
    const count = fs.readSync(fd, buffer, 0, buffer.length, 0);
    if (count !== stat.size) throw new Error(`file changed during read: ${relative}`);
    const after = fs.fstatSync(fd);
    const finalPath = fs.lstatSync(absolute);
    if (after.dev !== opened.dev || after.ino !== opened.ino || finalPath.dev !== opened.dev || finalPath.ino !== opened.ino || finalPath.nlink !== 1 || finalPath.size !== stat.size) throw new Error(`file identity changed during read: ${relative}`);
    const text = buffer.subarray(0, count).toString('utf8');
    if (!Buffer.from(text, 'utf8').equals(buffer.subarray(0, count))) throw new Error(`file is not strict UTF-8: ${relative}`);
    return text;
  } finally { fs.closeSync(fd); }
}

function assertSource(source, testSource) {
  const required = [
    'comfyHistoryMaxInputBytes', 'comfyHistoryMaxOutputBytes', 'comfyHistoryMaxRows',
    'duplicateFreeJSON', 'comfyExpectedGraphCount', 'normalizeComfyHistory',
    'if !utf8.Valid(raw)',
    'StatusStr != "success"', '!status.Completed', 'mapping.PublicPromptID != publicID',
    'row.Request.Plane != domain.PlaneComfy', 'row.Request.Adapter != "comfy"',
    'row.Request.ItemID != publicID', 'allowsAdapter(p, "comfy")',
    'normalized = append([]byte(nil), record...)',
    'outputBytes > comfyHistoryMaxOutputBytes',
    'len(publicKey) + len(normalized) + 3',
  ];
  for (const token of required) if (!source.includes(token)) throw new Error(`missing history contract source: ${token}`);
  const historyAllStart = source.indexOf('func (s *Server) handleComfyHistoryAll(');
  const historyAllEnd = source.indexOf('func (s *Server) handleComfyQueue(', historyAllStart);
  const historyAll = source.slice(historyAllStart, historyAllEnd);
  if (!historyAll.includes('rows, err := s.workloads.List(r.Context())\n\tif err != nil {')) throw new Error('history-all does not check store List errors');
  if (!historyAll.includes('row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID)')) throw new Error('history-all does not filter by owner before parsing');
  const declared = [...testSource.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
  if (declared.length !== tests.length || declared.some((name, index) => name !== tests[index])) throw new Error('history test inventory is missing, duplicated, or out of order');
  for (const token of [
    'invalidUTF8 :=', 'invalid-payload-utf8', 'string([]byte{0xff})', 'invalid UTF-8 payload was not rejected generically',
    'comfyHistoryMappingOverride', 'mapping.PublicPromptID = "different-public-id"',
    'mapping.WorkloadID = "mapping-sibling-workload"', 'mapping.TargetID = "different-target"',
    'mapping.BackendPromptID = "different-backend"', 'history is not an exact one-key object',
    'public record omitted outputs object', 'public record status changed', 'public prompt tuple identity=',
    'single history did not use native public shape', 'List failure was not generic 500',
    'owner filter parsed or exposed foreign history',
  ]) {
    if (!testSource.includes(token)) throw new Error(`history tests omit concrete UTF-8 negative control: ${token}`);
  }
  return true;
}

function verifyNegativeControl(label, mutatedSource, intendedToken, expectedDiagnostic) {
  if (mutatedSource.split(intendedToken).length !== 2) throw new Error(`negative control seam was not applied uniquely: ${label}`);
  if (mutatedSource === readBounded(sourcePath)) throw new Error(`negative control did not change source: ${label}`);
  try {
    assertSource(mutatedSource, readBounded(testPath));
  } catch (error) {
    if (error.message === expectedDiagnostic) return;
    throw new Error(`negative control rejected for unrelated reason (${label}): ${error.message}`);
  }
  throw new Error(`negative control survived: ${label}`);
}

function sourceOnly() {
  const source = readBounded(sourcePath);
  const testSource = readBounded(testPath);
  const legacyAPITests = readBounded('internal/api/workloads_http_test.go');
  const discoveryTests = readBounded('internal/api/comfy_discovery_http_test.go');
  const workloadTests = readBounded('internal/workloads/manager_test.go');
  const verifierSource = readBounded('scripts/verify-comfy-history.mjs');
  if (!verifierSource.includes('verifyNegativeControl') || !verifierSource.includes("effects: 'none'")) throw new Error('source-only verifier identity or effect declaration is missing');
  assertSource(source, testSource); // Positive control first.
  const inventories = [
    [legacyAPITests, [regressions[2]]],
    [discoveryTests, regressions.slice(0, 2)],
    [workloadTests, workloadRegressions],
  ];
  for (const [text, expected] of inventories) {
    const found = [...text.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
    for (const name of expected) if (!found.includes(name) || found.filter((candidate) => candidate === name).length !== 1) throw new Error(`legacy regression is missing or duplicated: ${name}`);
  }

  const nestedSingleAssignment = 'normalized, _ = json.Marshal(map[string]json.RawMessage{backendID: record})';
  const nestedSingle = replaceUnique(source, singleHistoryRecordLoop, nestedSingleHistoryRecordLoop, 'single shape negative control');
  verifyNegativeControl('single history retains backend nesting', nestedSingle, nestedSingleAssignment, 'missing history contract source: normalized = append([]byte(nil), record...)');
  const listGuard = 'rows, err := s.workloads.List(r.Context())\n\tif err != nil {';
  const ignoredListError = replaceUniqueInRegion(source, 'func (s *Server) handleComfyHistoryAll(', 'func (s *Server) handleComfyQueue(', listGuard, 'rows, err := s.workloads.List(r.Context())\n\tif false && err != nil {', 'List-error source-only');
  verifyNegativeControl('history-all ignores List error', ignoredListError, 'if false && err != nil {', 'history-all does not check store List errors');
  const ownerGuard = 'row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID)';
  const ownerBypass = replaceUniqueInRegion(source, 'func (s *Server) handleComfyHistoryAll(', 'func (s *Server) handleComfyQueue(', ownerGuard, 'row.Request.Plane != domain.PlaneComfy || false', 'owner filter negative control');
  verifyNegativeControl('history-all bypasses owner filtering', ownerBypass, 'row.Request.Plane != domain.PlaneComfy || false', 'history-all does not filter by owner before parsing');
  const wrongReasonFixture = replaceUniqueInRegion(ownerBypass, 'func duplicateFreeJSON(', 'func comfyExpectedGraphCount(', 'if !utf8.Valid(raw) {', 'if false {', 'unrelated diagnostic fixture');
  let unrelatedReasonRejected = false;
  try { verifyNegativeControl('wrong diagnostic must not count', wrongReasonFixture, 'row.Request.Plane != domain.PlaneComfy || false', 'history-all does not filter by owner before parsing'); }
  catch (error) { unrelatedReasonRejected = error.message.includes('negative control rejected for unrelated reason') && error.message.includes('if !utf8.Valid(raw)'); }
  if (!unrelatedReasonRejected) throw new Error('negative control accepted an unrelated source diagnostic');
  const utf8Bypass = replaceUniqueInRegion(source, 'func duplicateFreeJSON(', 'func comfyExpectedGraphCount(', 'if !utf8.Valid(raw) {', 'if false {', 'UTF-8 validator negative control');
  verifyNegativeControl('history accepts invalid UTF-8', utf8Bypass, 'if false {', 'missing history contract source: if !utf8.Valid(raw)');
  verifyTranscriptOracle();
  return { mode: 'source-only', ownedFiles: 3, exactTests: tests.length, regressionInventory: regressions.length + workloadRegressions.length, sourceMutantsRejected: 4, mutantsRejected: 3, effects: 'none' };
}

function assertProcessResult(result, expectedStatus, label) {
  if (!result || result.error || result.signal || typeof result.status !== 'number' || !Number.isInteger(result.status) || result.status !== expectedStatus) {
    throw new Error(`${label} did not return exact status ${expectedStatus} (status=${result?.status ?? 'null'}, signal=${result?.signal ?? ''}, error=${result?.error?.message ?? ''})`);
  }
}

function packageName(packagePath) {
  return packagePath === './internal/api' ? 'vram-governor/internal/api' : 'vram-governor/internal/workloads';
}

function packageSummarySeconds(output, expectedPackage, result) {
  const escaped = expectedPackage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = result === 'pass'
    ? new RegExp(`^ok[ \\t]{1,3}\\t${escaped}\\t(\\d+(?:\\.\\d+)?)s\\n$`)
    : new RegExp(`^FAIL\\t${escaped}\\t(\\d+(?:\\.\\d+)?)s\\n$`);
  const match = typeof output === 'string' ? output.match(pattern) : null;
  if (!match) return null;
  const seconds = Number(match[1]);
  return Number.isFinite(seconds) && seconds >= 0 && seconds <= 120 ? seconds : null;
}

function parseGoJSON(output, expected, expectedPackage, mutant = null) {
  if (typeof output !== 'string' || Buffer.byteLength(output, 'utf8') > (16 << 20)) throw new Error('Go transcript is missing or exceeds its bound');
  const events = output.split(/\r?\n/).filter((line) => line.length > 0).map((line) => {
    let event;
    try { event = JSON.parse(line); } catch { throw new Error('malformed Go JSON event'); }
    if (!event || Array.isArray(event) || typeof event !== 'object' || event.Package !== expectedPackage || typeof event.Action !== 'string') throw new Error('foreign or malformed Go event');
    if (Object.keys(event).some((key) => !['Action', 'Package', 'Test', 'Output', 'Elapsed', 'Time'].includes(key))) throw new Error('unsupported Go event field');
    if (event.Time !== undefined && typeof event.Time !== 'string') throw new Error('invalid Go event time');
    if (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0 || event.Elapsed > 120)) throw new Error('invalid Go elapsed time');
    if (event.Action === 'output' ? typeof event.Output !== 'string' : event.Output !== undefined) throw new Error('invalid Go output field');
    return event;
  });
  const state = new Map();
  const parents = [];
  let packageState = '';
  let passLine = false;
  let packageSummary = false;
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (e.Test === undefined) {
      if (e.Action === 'start') {
        if (packageState || i !== 0) throw new Error('duplicate or late package start');
        packageState = 'running';
      } else if (e.Action === 'output') {
        if (packageState !== 'running' || [...state].some(([name, s]) => !name.endsWith('\0output') && s !== 'pass' && s !== 'fail')) throw new Error('package output before test completion');
        if (e.Output === 'PASS\n') { if (passLine || packageSummary) throw new Error('duplicate or late PASS text'); passLine = true; }
        else if (packageSummarySeconds(e.Output, expectedPackage, 'pass') !== null && passLine && !packageSummary) packageSummary = true;
        else if (mutant && e.Output === 'FAIL\n') { if (passLine) throw new Error('late FAIL text'); passLine = 'FAIL'; }
        else if (mutant && passLine === 'FAIL' && packageSummarySeconds(e.Output, expectedPackage, 'fail') !== null) packageSummary = true;
        else throw new Error('unexpected package output or summary');
      } else if (['pass', 'fail'].includes(e.Action)) {
        if (packageState !== 'running' || expected.some((n) => state.get(n) !== (mutant?.test === n ? 'fail' : 'pass'))) throw new Error('package terminal before exact tests');
        if (e.Action === 'pass' && (!passLine || !packageSummary || e.Elapsed === undefined)) throw new Error('package pass lacks terminal evidence');
        if (mutant && (e.Action !== 'fail' || !packageSummary || passLine !== 'FAIL' || e.Elapsed === undefined)) throw new Error('mutant package failure lacks terminal evidence');
        if (!mutant && e.Action !== 'pass') throw new Error('unexpected package failure');
        packageState = e.Action;
        if (i !== events.length - 1) throw new Error('event after package terminal');
      } else throw new Error(`unexpected package action ${e.Action}`);
      continue;
    }
    if (packageState !== 'running' || typeof e.Test !== 'string' || !e.Test) throw new Error('test event outside active package');
    const parent = e.Test.split('/')[0];
    if (!expected.includes(parent)) throw new Error(`foreign test ${e.Test}`);
    if (e.Action === 'run') {
      if (state.has(e.Test)) throw new Error(`duplicate test ${e.Test}`);
      let observedAncestor = '';
      for (let slash = e.Test.lastIndexOf('/'); slash > 0; slash = e.Test.lastIndexOf('/', slash - 1)) {
        const candidate = e.Test.slice(0, slash);
        if (state.has(candidate)) { observedAncestor = candidate; break; }
      }
      if (e.Test.includes('/') && (!observedAncestor || state.get(observedAncestor) !== 'running')) throw new Error(`nested test lacks its longest active observed ancestor ${e.Test}`);
      state.set(e.Test, 'running');
      if (!e.Test.includes('/')) parents.push(e.Test);
    } else if (['pass', 'fail', 'skip'].includes(e.Action)) {
      if (state.get(e.Test) !== 'running' || [...state].some(([n, s]) => n.startsWith(e.Test + '/') && s === 'running')) throw new Error(`invalid terminal ordering ${e.Test}`);
      state.set(e.Test, e.Action);
    } else if (e.Action === 'output') {
      if (state.get(e.Test) !== 'running') throw new Error(`output outside test ${e.Test}`);
      state.set(`${e.Test}\0output`, (state.get(`${e.Test}\0output`) || '') + e.Output);
    } else throw new Error(`unexpected test action ${e.Action}`);
  }
  if (parents.length !== expected.length || parents.some((n, i) => n !== expected[i])) throw new Error('test inventory missing, duplicate, foreign, or out of order');
  const testStates = [...state].filter(([name]) => !name.endsWith('\0output'));
  const failed = testStates.filter(([, result]) => result === 'fail').map(([name]) => name);
  if (mutant) {
    const owner = mutant.ownerPath || mutant.test;
    const parts = owner.split('/');
    if (parts[0] !== mutant.test || parts.some((part) => !/^[A-Za-z0-9_]+$/.test(part))) throw new Error('mutant assertion owner is not nested beneath its exact expected test');
    const ancestors = parts.map((_, index) => parts.slice(0, parts.length - index).join('/'));
    if (failed.length !== ancestors.length || failed.some((name) => !ancestors.includes(name)) || state.get(owner) !== 'fail') throw new Error('mutant did not fail at the exact assertion owner and slash ancestors');
    if (testStates.some(([name, result]) => !ancestors.includes(name) && result !== 'pass')) throw new Error('mutant had skipped, incomplete, or unrelated failed nested tests');
    const text = state.get(`${owner}\0output`) || '';
    if (!text.includes(mutant.marker)) throw new Error('mutant failure marker missing');
    for (const [key, value] of state) if (key.endsWith('\0output') && key !== `${owner}\0output` && value.includes(mutant.marker)) throw new Error('mutant marker belongs to another test');
  } else if (testStates.length === 0 || testStates.some(([, result]) => result !== 'pass')) throw new Error('test missing PASS or was skipped/failed');
  if (!packageState || (mutant ? packageState !== 'fail' : packageState !== 'pass')) throw new Error('package lacks exact terminal state');
}

function verifyTranscriptOracle() {
  const event = (Action, Test, extra = {}) => ({ Action, Package: 'fixture', ...(Test ? { Test } : {}), ...extra });
  const transcript = (events) => events.map((e) => JSON.stringify(e)).join('\n');
  const good = [event('start'), event('run', 'TestA'), event('pass', 'TestA', { Elapsed: 0 }), event('output', undefined, { Output: 'PASS\n' }), event('output', undefined, { Output: 'ok  \tfixture\t0.001s\n' }), event('pass', undefined, { Elapsed: 0.002 })];
  parseGoJSON(transcript(good), ['TestA'], 'fixture');
  const nested = [event('start'), event('run', 'TestA'), event('run', 'TestA/child'), event('output', 'TestA/child', { Output: 'nested pass\n' }), event('pass', 'TestA/child', { Elapsed: 0 }), event('pass', 'TestA', { Elapsed: 0 }), ...good.slice(3)];
  parseGoJSON(transcript(nested), ['TestA'], 'fixture');
  const slashNested = [event('start'), event('run', 'TestA'), event('run', 'TestA/a/b'), event('pass', 'TestA/a/b', { Elapsed: 0 }), event('pass', 'TestA', { Elapsed: 0 }), ...good.slice(3)];
  parseGoJSON(transcript(slashNested), ['TestA'], 'fixture');
  const observedMiddle = [event('start'), event('run', 'TestA'), event('run', 'TestA/a'), event('run', 'TestA/a/b/c'), event('pass', 'TestA/a/b/c', { Elapsed: 0 }), event('pass', 'TestA/a', { Elapsed: 0 }), event('pass', 'TestA', { Elapsed: 0 }), ...good.slice(3)];
  parseGoJSON(transcript(observedMiddle), ['TestA'], 'fixture');
  const buildFailure = [
    event('start'),
    event('output', undefined, { Output: '# fixture [fixture.test]\ncompiler error: declared and not used: record\n' }),
    event('output', undefined, { Output: 'FAIL\tfixture [build failed]\n' }),
    event('fail', undefined, { Elapsed: 0.001 }),
  ];
  let buildFailureDiagnostic = '';
  try { parseGoJSON(transcript(buildFailure), ['TestA'], 'fixture', { test: 'TestA', marker: 'intended assertion marker' }); }
  catch (error) { buildFailureDiagnostic = error.message; }
  if (buildFailureDiagnostic !== 'unexpected package output or summary') throw new Error(`build-failure transcript was not rejected before behavioral evidence: ${buildFailureDiagnostic || 'accepted'}`);
  const bad = [
    good.slice(0, 1),
    [good[0], event('run', 'TestA'), event('skip', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('fail', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'Foreign'), event('pass', 'Foreign'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA'), event('pass', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('pass', 'TestA'), event('run', 'TestA/child'), event('pass', 'TestA/child'), ...good.slice(3)],
    [good[0], event('run', 'TestA/child'), event('pass', 'TestA/child'), event('pass', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA/child'), event('pass', 'TestA'), event('pass', 'TestA/child'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA/child'), event('skip', 'TestA/child'), event('pass', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA/a/b'), event('pass', 'TestA/a/b'), event('pass', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('pass', 'TestA'), event('run', 'TestA/a/b'), event('pass', 'TestA/a/b'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA/a'), event('pass', 'TestA/a'), event('run', 'TestA/a/b'), event('pass', 'TestA/a/b'), event('pass', 'TestA'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA/child'), event('pass', 'TestA'), event('pass', 'TestA/child'), ...good.slice(3)],
    [good[0], event('run', 'TestA'), event('run', 'TestA/child'), event('pass', 'TestA'), event('pass', 'TestA/child'), event('output', undefined, { Output: 'PASS\n' }), event('output', undefined, { Output: 'ok  \tfixture\t0.001s\n' }), event('pass', undefined, { Elapsed: 0.002 })],
    [good[0], event('run', 'TestA'), event('run', 'TestA/child'), event('pass', undefined, { Elapsed: 0.002 })],
    [good[0], ...good.slice(1, 4), event('output', undefined, { Output: 'ok\tfixture\t0.001s\n' }), good[5]],
    [good[0], ...good.slice(1, 4), event('output', undefined, { Output: 'ok  \tforeign/package\t0.001s\n' }), good[5]],
    [good[0], ...good.slice(1, 4), event('output', undefined, { Output: 'ok  \tfixture\t(cached)\n' }), good[5]],
    [good[0], ...good.slice(1, 4), event('output', undefined, { Output: 'ok  \tfixture\t1e400s\n' }), good[5]],
    [good[0], ...good.slice(1, 4), event('output', undefined, { Output: 'ok  \tfixture\t120.001s\n' }), good[5]],
  ];
  for (const fixture of bad) { let rejected = false; try { parseGoJSON(transcript(fixture), ['TestA'], 'fixture'); } catch { rejected = true; } if (!rejected) throw new Error('Go transcript negative control accepted'); }
}

function replaceUnique(source, before, after, label) {
  const at = source.indexOf(before);
  if (at < 0 || source.indexOf(before, at + before.length) >= 0) throw new Error(`mutant seam is missing or ambiguous: ${label}`);
  const changed = source.slice(0, at) + after + source.slice(at + before.length);
  if (changed === source) throw new Error(`mutant seam made no change: ${label}`);
  return changed;
}

function replaceUniqueInRegion(source, startToken, endToken, before, after, label) {
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start + startToken.length);
  if (start < 0 || end < 0) throw new Error(`mutant region is missing: ${label}`);
  const region = source.slice(start, end);
  return source.slice(0, start) + replaceUnique(region, before, after, label) + source.slice(end);
}

function verifyOverlayIdentity(directory, directoryIdentity, expectedFiles) {
  const currentDir = fs.lstatSync(directory);
  if (!currentDir.isDirectory() || currentDir.isSymbolicLink() || currentDir.dev !== directoryIdentity.dev || currentDir.ino !== directoryIdentity.ino) throw new Error('overlay directory identity changed');
  const names = fs.readdirSync(directory).sort();
  const expectedNames = Object.keys(expectedFiles).sort();
  if (names.length !== expectedNames.length || names.some((name, i) => name !== expectedNames[i])) throw new Error('overlay directory contains unexpected entries');
  for (const name of expectedNames) {
    const file = path.join(directory, name);
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size !== expectedFiles[name].size || stat.dev !== expectedFiles[name].dev || stat.ino !== expectedFiles[name].ino) throw new Error(`overlay identity changed: ${name}`);
    const content = fs.readFileSync(file);
    if (crypto.createHash('sha256').update(content).digest('hex') !== expectedFiles[name].sha256) throw new Error(`overlay content changed: ${name}`);
  }
}

function protocol() {
  const source = readBounded(sourcePath);
  const apiInventory = [...regressions.slice(0, 2), ...tests, regressions[2]];
  const goTest = (packagePath, names, overlayPath = '') => {
    const args = ['test', '-json'];
    if (overlayPath) args.push(`-overlay=${overlayPath}`);
    args.push(packagePath, '-run', `^(${names.join('|')})$`, '-count=1');
    const result = spawnSync('go', args, { cwd: root, encoding: 'utf8', timeout: 120000, maxBuffer: 16 << 20, windowsHide: true });
    return result;
  };
  const apiPositive = goTest('./internal/api', apiInventory);
  assertProcessResult(apiPositive, 0, 'API test inventory');
  parseGoJSON(apiPositive.stdout, apiInventory, packageName('./internal/api'));
  const workloadPositive = goTest('./internal/workloads', workloadRegressions);
  assertProcessResult(workloadPositive, 0, 'workload test inventory');
  parseGoJSON(workloadPositive.stdout, workloadRegressions, packageName('./internal/workloads'));
  const mutants = [
    { name: 'single-shape', test: tests[0], marker: 'single history did not use native public shape', changed: replaceUniqueInRegion(source, 'func normalizeComfyHistory(', 'func (s *Server) handleComfyHistory(', singleHistoryRecordLoop, nestedSingleHistoryRecordLoop, 'single-shape') },
    { name: 'list-error', test: tests[4], marker: 'List failure was not generic 500', changed: replaceUniqueInRegion(source, 'func (s *Server) handleComfyHistoryAll(', 'func (s *Server) handleComfyQueue(', 'rows, err := s.workloads.List(r.Context())\n\tif err != nil {', 'rows, err := s.workloads.List(r.Context())\n\tif false && err != nil {', 'list-error') },
    { name: 'owner-guard', test: tests[3], marker: 'owner filter parsed or exposed foreign history', changed: replaceUniqueInRegion(source, 'func (s *Server) handleComfyHistoryAll(', 'func (s *Server) handleComfyQueue(', 'row.Request.Plane != domain.PlaneComfy || (!hasScope(p, "admin") && row.Request.OwnerID != p.OwnerID)', 'row.Request.Plane != domain.PlaneComfy || false', 'owner-guard') },
  ];
  for (const mutant of mutants) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'comfy-history-overlay-'));
    const directoryIdentity = fs.lstatSync(directory);
    const overlayFile = path.join(directory, 'mutant.go');
    const overlayPath = path.join(directory, 'overlay.json');
    const overlayJSON = JSON.stringify({ Replace: { [path.resolve(root, sourcePath)]: overlayFile } });
    const payloads = { 'mutant.go': Buffer.from(mutant.changed, 'utf8'), 'overlay.json': Buffer.from(overlayJSON, 'utf8') };
    const identities = {};
    let childInvoked = false;
    let ordinaryChildExitObserved = false;
    try {
      for (const [name, payload] of Object.entries(payloads)) {
        fs.writeFileSync(path.join(directory, name), payload, { flag: 'wx', mode: 0o600 });
        const stat = fs.lstatSync(path.join(directory, name));
        identities[name] = { dev: stat.dev, ino: stat.ino, size: payload.length, sha256: crypto.createHash('sha256').update(payload).digest('hex') };
      }
      verifyOverlayIdentity(directory, directoryIdentity, identities);
      childInvoked = true;
      const result = goTest('./internal/api', [mutant.test], overlayPath);
      ordinaryChildExitObserved = !!result && !result.error && !result.signal && typeof result.status === 'number' && Number.isInteger(result.status);
      assertProcessResult(result, 1, `${mutant.name} mutant`);
      parseGoJSON(result.stdout, [mutant.test], packageName('./internal/api'), { test: mutant.test, marker: mutant.marker });
      verifyOverlayIdentity(directory, directoryIdentity, identities);
    } finally {
      if (childInvoked && !ordinaryChildExitObserved) {
        const metadata = JSON.stringify(Object.fromEntries(Object.entries(identities).map(([name, identity]) => [name, { size: identity.size, sha256: identity.sha256, dev: identity.dev, ino: identity.ino }])));
        throw new Error(`uncertain Go child settlement; preserving exact private overlay directory=${directory} identity=${directoryIdentity.dev}:${directoryIdentity.ino} files=${metadata.slice(0, 1200)}`);
      }
      verifyOverlayIdentity(directory, directoryIdentity, identities);
      for (const name of Object.keys(identities).sort()) fs.unlinkSync(path.join(directory, name));
      if (fs.readdirSync(directory).length !== 0) throw new Error('overlay directory did not become empty');
      const finalDir = fs.lstatSync(directory);
      if (!finalDir.isDirectory() || finalDir.isSymbolicLink() || finalDir.dev !== directoryIdentity.dev || finalDir.ino !== directoryIdentity.ino) throw new Error('overlay directory changed before cleanup');
      fs.rmdirSync(directory);
    }
  }
  return { mode: 'protocol', positiveTests: apiInventory.length + workloadRegressions.length, mutantsRejected: mutants.length, effects: 'bounded go test -json inventories and private source overlays' };
}

try {
  if (mode === '--mode=source-only') {
    const result = sourceOnly();
    console.log('public Comfy history source controls passed');
    console.log(JSON.stringify(result));
  } else if (mode === '--mode=protocol') {
    const result = protocol();
    console.log('public Comfy history protocol verification passed');
    console.log(JSON.stringify(result));
  } else {
    throw new Error('usage: node scripts/verify-comfy-history.mjs --mode=source-only|--mode=protocol');
  }
} catch (error) {
  console.error(String(error.message || error).slice(0, 2000));
  process.exitCode = 1;
}
