import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
const typescript = require(path.join(root, 'web/ui/node_modules/typescript/lib/typescript.js'));
const controlsSource = readFileSync(path.join(root, 'web/ui/src/runtimeControls.ts'), 'utf8');
const adminSource = readFileSync(path.join(root, 'web/ui/src/admin.tsx'), 'utf8');
const commonSource = readFileSync(path.join(root, 'web/ui/src/common.tsx'), 'utf8');

function extractFunction(source, declaration, nextDeclaration) {
  const startToken = `\n${declaration}`;
  const endToken = `\n${nextDeclaration}`;
  const start = source.indexOf(startToken);
  const end = source.indexOf(endToken, start + startToken.length);
  if (start < 0 || end <= start || source.indexOf(startToken, start + startToken.length) !== -1) {
    throw new Error(`function source boundary is missing or ambiguous: ${declaration}`);
  }
  return source.slice(start + 1, end + 1);
}

function loadActualExports() {
  const result = typescript.transpileModule(controlsSource, {
    compilerOptions: { module: typescript.ModuleKind.CommonJS, target: typescript.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  const errors = (result.diagnostics ?? []).filter((diagnostic) => diagnostic.category === typescript.DiagnosticCategory.Error);
  if (errors.length) throw new Error(`runtimeControls.ts transpilation failed: ${errors.map((item) => typescript.flattenDiagnosticMessageText(item.messageText, '\n')).join('; ')}`);
  const module = { exports: {} };
  vm.runInNewContext(result.outputText, { module, exports: module.exports }, { filename: 'runtimeControls.transpiled.cjs', timeout: 1_000 });
  if (typeof module.exports.requestRuntimeTransition !== 'function' ||
      typeof module.exports.recoverRuntimeTransition !== 'function' ||
      typeof module.exports.retireSettledRequestKeys !== 'function') {
    throw new Error('actual runtime transition exports were not emitted');
  }
  return module.exports;
}

function loadActualCardHandler() {
  const sourceFile = typescript.createSourceFile('admin.tsx', adminSource, typescript.ScriptTarget.Latest, true, typescript.ScriptKind.TSX);
  const components = [];
  function visit(node) {
    if (typescript.isFunctionDeclaration(node) && node.name?.text === 'RuntimeControlCard') components.push(node);
    typescript.forEachChild(node, visit);
  }
  visit(sourceFile);
  if (components.length !== 1) throw new Error('expected one actual RuntimeControlCard declaration');
  const handlers = components[0].body.statements.filter((node) => typescript.isFunctionDeclaration(node) && node.name?.text === 'changeResidency');
  if (handlers.length !== 1) throw new Error('expected one actual changeResidency handler');
  const handlerText = handlers[0].getText(sourceFile).replace(/^async function changeResidency/, 'async function changeResidency');
  const compiled = typescript.transpileModule(`const extractedChangeResidency = ${handlerText};`, {
    compilerOptions: { module: typescript.ModuleKind.None, target: typescript.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  const errors = (compiled.diagnostics ?? []).filter((diagnostic) => diagnostic.category === typescript.DiagnosticCategory.Error);
  if (errors.length) throw new Error(`actual card handler transpilation failed: ${errors.map((item) => typescript.flattenDiagnosticMessageText(item.messageText, '\n')).join('; ')}`);
  return new Function('target', 'model', 'requestKeys', 'crypto', 'requestRuntimeTransition', 'recoverRuntimeTransition', 'retireSettledRequestKeys', 'residencyTransitions', 'api', 'setBusy', 'setMessage', 'setMessageKind', 'refresh',
    `${compiled.outputText}\nreturn extractedChangeResidency;`);
}

function verifyCardWiring() {
  const classifier = extractFunction(controlsSource, 'function classifyTransition(', 'function exactCurrentTier(');
  if (classifier.includes('transition.observed_tier')) {
    throw new Error('historical transition observation must not be treated as current residency');
  }
  const card = extractFunction(adminSource, 'function RuntimeControlCard(', 'function ModelsPage(').replace(/\s+/g, '');
  if (!card.includes('requestRuntimeTransition(api,target.id,model,tier,requestKey)') ||
      !card.includes('recoverRuntimeTransition(api,target.id,model,tier,requestKey)') ||
      !card.includes('retireSettledRequestKeys(requestKeys.current,residencyTransitions,target.id)') ||
      !card.includes('requestKeys=useRef(newMap<string,string>())') ||
      !card.includes('requestKeys.current.get(keyScope)') || !card.includes('requestKeys.current.set(keyScope,requestKey)') ||
      !card.includes('changeResidency("hot_vram")') || !card.includes('changeResidency("cold_disk")')) {
    throw new Error('runtime model load/unload buttons are not wired to the guarded transition helper');
  }
  const modelsPage = extractFunction(adminSource, 'function ModelsPage(', 'function TelemetryChart(').replace(/\s+/g, '');
  if (!modelsPage.includes('residencyTransitions={operations}')) {
    throw new Error('runtime controls must receive the overview transition history for exact-key retirement');
  }
  if (!card.includes('finally{try{refresh()}finally{setBusy(false)}}') ||
      !card.includes('Request${requestKey}') || !card.includes('notafreshruntimequery') ||
      !card.includes('Retry/recoveronlywiththissamerequestkey') ||
      !card.includes('doesnotprovenoruntimeeffectoccurred') || !card.includes('nonewPOSTwillbesent') ||
      card.includes('Runtimereports') || /requestRuntimeTransition\([^)]*crypto\.randomUUID/.test(card)) {
    throw new Error('runtime control must retain and expose the request key, refresh after every outcome, and distinguish controller projection from live runtime');
  }
  if (card.includes('command:"load_model"') || card.includes('command:"unload_model"') || card.includes('args:{target_id:target.id,model}')) {
    throw new Error('runtime model load/unload still uses a raw node command');
  }
  if (!card.includes('{target.supports_model_lifecycle&&') || !card.includes('{target.supports_runtime_profile_switch&&') ||
      !card.includes('command:"switch_runtime_profile"')) {
    throw new Error('existing lifecycle/profile capability gates or signed profile-switch command path were not preserved');
  }
  const normalizedCommon = commonSource.replace(/\s+/g, '');
  if (!normalizedCommon.includes('headers.set("X-CSRF-Token",csrf)') || !normalizedCommon.includes('credentials:"same-origin"')) {
    throw new Error('shared API helper no longer provides same-origin CSRF transport');
  }
}

function transitionResponse({ targetId, model, observedTier, transition = null }) {
  return {
    residency: { target_id: targetId, model, observed_tier: observedTier },
    transitions: transition ? [transition] : null,
  };
}

async function verifyActualHelper() {
  const { requestRuntimeTransition, recoverRuntimeTransition, retireSettledRequestKeys } = loadActualExports();
  const calls = [];
  let mockResponse = transitionResponse({
    targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
    transition: { id: 'transition-load', idempotency_key: 'load-key-001', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'planned' },
  });
  const mockApi = async (url, init) => { calls.push({ url, init }); return mockResponse; };

  const load = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'load-key-001');
  assert.deepEqual(JSON.parse(JSON.stringify(load)), { state: 'pending', tier: 'hot_vram', requestKey: 'load-key-001', transitionId: 'transition-load', transitionStatus: 'planned', observedTier: 'cold_disk' });
  assert.equal(calls[0].url, '/admin/api/residency/transition');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['Idempotency-Key'], 'load-key-001');
  assert.deepEqual(JSON.parse(calls[0].init.body), { target_id: 'target-a', model: 'model one', desired_tier: 'hot_vram' });

  mockResponse = transitionResponse({ targetId: 'target-a', model: 'model one', observedTier: 'cold_disk' });
  const unload = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'cold_disk', 'unload-key-002');
  assert.deepEqual(JSON.parse(JSON.stringify(unload)), { state: 'recorded', tier: 'cold_disk', requestKey: 'unload-key-002', observedTier: 'cold_disk' });
  assert.equal(calls[1].url, '/admin/api/residency/transition');
  assert.deepEqual(JSON.parse(calls[1].init.body), { target_id: 'target-a', model: 'model one', desired_tier: 'cold_disk' });

  mockResponse = transitionResponse({
    targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
    transition: { id: 'transition-running', idempotency_key: 'running-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'running' },
  });
  const running = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'running-key');
  assert.deepEqual(JSON.parse(JSON.stringify(running)), { state: 'pending', tier: 'hot_vram', requestKey: 'running-key', transitionId: 'transition-running', transitionStatus: 'running', observedTier: 'cold_disk' });

  mockResponse = transitionResponse({
    targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
    transition: { id: 'transition-succeeded-unobserved', idempotency_key: 'unobserved-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'succeeded' },
  });
  const successWithoutObservation = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'unobserved-key');
  assert.deepEqual(JSON.parse(JSON.stringify(successWithoutObservation)), { state: 'terminal', tier: 'hot_vram', requestKey: 'unobserved-key', transitionId: 'transition-succeeded-unobserved', transitionStatus: 'succeeded', currentTier: 'cold_disk' });
  assert.notEqual(successWithoutObservation.currentTier, 'hot_vram', 'historical success must not imply that the model is currently loaded');

  const historicalHotSuccess = { id: 'historical-hot-success', idempotency_key: 'historical-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'succeeded', observed_tier: 'hot_vram' };
  const recoveredWithColdProjection = await recoverRuntimeTransition(async () => ({
    residencies: [{ target_id: 'target-a', model: 'model one', observed_tier: 'cold_disk' }], transitions: [historicalHotSuccess],
  }), 'target-a', 'model one', 'hot_vram', 'historical-key');
  assert.deepEqual(JSON.parse(JSON.stringify(recoveredWithColdProjection)), {
    state: 'terminal', tier: 'hot_vram', requestKey: 'historical-key', transitionId: 'historical-hot-success',
    transitionStatus: 'succeeded', currentTier: 'cold_disk',
  }, 'recovery must separate historical terminal status from the current controller projection');
  const recoveredWithoutProjection = await recoverRuntimeTransition(async () => ({
    residencies: [], transitions: [historicalHotSuccess],
  }), 'target-a', 'model one', 'hot_vram', 'historical-key');
  assert.deepEqual(JSON.parse(JSON.stringify(recoveredWithoutProjection)), {
    state: 'terminal', tier: 'hot_vram', requestKey: 'historical-key', transitionId: 'historical-hot-success', transitionStatus: 'succeeded',
  }, 'a historical success without a current residency row must not claim current residency');
  const recoveredWithUnrelatedProjection = await recoverRuntimeTransition(async () => ({
    residencies: [{ target_id: 'other-target', model: 'model one', observed_tier: 'hot_vram' }], transitions: [historicalHotSuccess],
  }), 'target-a', 'model one', 'hot_vram', 'historical-key');
  assert.equal(recoveredWithUnrelatedProjection.currentTier, undefined, 'a different target projection cannot stand in for the requested target');

  const wrongTupleKeyMap = new Map([
    [JSON.stringify(['target-a', 'model one', 'hot_vram']), 'historical-key'],
    [JSON.stringify(['target-a', 'model one', 'cold_disk']), 'cold-request'],
  ]);
  for (const wrongHistory of [
    { ...historicalHotSuccess, idempotency_key: 'different-key' },
    { ...historicalHotSuccess, target_id: 'other-target' },
    { ...historicalHotSuccess, model: 'other model' },
    { ...historicalHotSuccess, to_tier: 'cold_disk' },
  ]) {
    retireSettledRequestKeys(wrongTupleKeyMap, [wrongHistory], 'target-a');
    assert.equal(wrongTupleKeyMap.size, 2, 'wrong key or tuple must not retire a held request key');
  }
  retireSettledRequestKeys(wrongTupleKeyMap, [historicalHotSuccess], 'target-a');
  assert.deepEqual([...wrongTupleKeyMap.values()], ['cold-request'], 'only the exact succeeded transition may retire its matching key');
  const failedKeyMap = new Map([[JSON.stringify(['target-a', 'model one', 'cold_disk']), 'failed-unload-key']]);
  retireSettledRequestKeys(failedKeyMap, [{ id: 'failed-unload', idempotency_key: 'failed-unload-key', target_id: 'target-a', model: 'model one', to_tier: 'cold_disk', status: 'failed' }], 'target-a');
  assert.equal(failedKeyMap.size, 1, 'a failed terminal transition must not retire its held request key');
  assert.equal(failedKeyMap.get(JSON.stringify(['target-a', 'model one', 'cold_disk'])), 'failed-unload-key');

  mockResponse = transitionResponse({ targetId: 'target-a', model: 'model one', observedTier: 'cold_disk' });
  const missing = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'missing-transition-key');
  assert.equal(missing.state, 'unknown');
  assert.equal(calls.at(-1).url, '/admin/api/residency');

  const exactRunning = { id: 'transition-recovered', idempotency_key: 'post-error-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'running' };
  const recoveryCalls = [];
  const recovered = await requestRuntimeTransition(async (url, init) => {
    recoveryCalls.push({ url, init });
    if (url.endsWith('/transition')) throw new Error('request timed out after submission');
    return { residencies: [], transitions: [exactRunning] };
  }, 'target-a', 'model one', 'hot_vram', 'post-error-key');
  assert.deepEqual(JSON.parse(JSON.stringify(recovered)), { state: 'pending', tier: 'hot_vram', requestKey: 'post-error-key', transitionId: 'transition-recovered', transitionStatus: 'running' });
  assert.deepEqual(recoveryCalls.map((call) => call.url), ['/admin/api/residency/transition', '/admin/api/residency']);
  assert.equal(recoveryCalls[0].init.headers['Idempotency-Key'], 'post-error-key');

  for (const mismatch of [
    { ...exactRunning, idempotency_key: 'other-key' },
    { ...exactRunning, target_id: 'other-target' },
    { ...exactRunning, model: 'other model' },
    { ...exactRunning, to_tier: 'cold_disk' },
  ]) {
    const outcome = await requestRuntimeTransition(async (url) => {
      if (url.endsWith('/transition')) throw new Error('connection lost');
      return { residencies: [], transitions: [mismatch] };
    }, 'target-a', 'model one', 'hot_vram', 'post-error-key');
    assert.equal(outcome.state, 'unknown', 'recovery must require exact request key and target/model/tier tuple');
  }

  const exactSucceededMismatch = { id: 'transition-projection-mismatch', idempotency_key: 'projection-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'succeeded', observed_tier: 'cold_disk' };
  const projectionMismatch = await requestRuntimeTransition(async (url) => url.endsWith('/transition')
    ? transitionResponse({ targetId: 'target-a', model: 'model one', observedTier: 'cold_disk', transition: exactSucceededMismatch })
    : { residencies: [], transitions: [] }, 'target-a', 'model one', 'hot_vram', 'projection-key');
  assert.deepEqual(JSON.parse(JSON.stringify(projectionMismatch)), {
    state: 'terminal', tier: 'hot_vram', requestKey: 'projection-key', transitionId: 'transition-projection-mismatch',
    transitionStatus: 'succeeded', currentTier: 'cold_disk',
  }, 'historical success and the current controller projection must be reported separately');

  // Existing identities are reconciled with GET only, never replayed with POST.
  const readOnlyCalls = [];
  const stillPending = await recoverRuntimeTransition(async (url, init) => {
    readOnlyCalls.push({ url, init });
    return { residencies: [], transitions: [] };
  }, 'target-a', 'model one', 'cold_disk', 'stable-retry-key');
  assert.equal(stillPending.state, 'unknown');
  assert.deepEqual(readOnlyCalls.map((call) => [call.url, call.init.method]), [['/admin/api/residency', 'GET']]);

  let invalidCalls = 0;
  const neverCall = async () => { invalidCalls++; return mockResponse; };
  for (const args of [
    ['', 'model one', 'hot_vram', 'k'],
    ['target-a', '  ', 'hot_vram', 'k'],
    ['target-a', 'model one', 'warm_ram', 'k'],
    ['target-a', 'model one', 'cold_disk', '  '],
  ]) {
    await assert.rejects(() => requestRuntimeTransition(neverCall, ...args));
  }
  assert.equal(invalidCalls, 0, 'invalid input must not issue an API request');

  mockResponse = transitionResponse({
    targetId: 'other-target', model: 'model one', observedTier: 'hot_vram',
  });
  const mismatchedResponse = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'mismatch-key');
  assert.equal(mismatchedResponse.state, 'unknown');
  assert.equal(mismatchedResponse.requestKey, 'mismatch-key');
  assert.equal(calls.at(-1).url, '/admin/api/residency', 'mismatched POST response should use only read-only recovery');

  mockResponse = transitionResponse({
    targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
    transition: { id: 'transition-failed', idempotency_key: 'failed-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'failed', error: 'runtime rejected model' },
  });
  const failed = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'failed-key');
  assert.equal(failed.state, 'terminal');
  assert.equal(failed.transitionStatus, 'failed');
  assert.equal(failed.requestKey, 'failed-key');
  assert.equal(failed.currentTier, 'cold_disk', 'terminal failure must carry the separate current controller projection');

  mockResponse = transitionResponse({
    targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
    transition: { id: 'transition-attention', idempotency_key: 'attention-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'manual_reconciliation_required', error: 'operator review required' },
  });
  const attention = await requestRuntimeTransition(mockApi, 'target-a', 'model one', 'hot_vram', 'attention-key');
  assert.deepEqual(JSON.parse(JSON.stringify(attention)), { state: 'attention', tier: 'hot_vram', requestKey: 'attention-key', transitionId: 'transition-attention', message: 'operator review required' });

  const lookupFailed = await requestRuntimeTransition(async (url) => {
    if (url.endsWith('/transition')) throw new Error('API rejected request');
    throw new Error('lookup unavailable');
  }, 'target-a', 'model one', 'hot_vram', 'api-error-key');
  assert.equal(lookupFailed.state, 'unknown');
  assert.match(lookupFailed.message, /read-only recovery lookup failed/);

  const postKeys = [];
  const apiCalls = [];
  const messages = [];
  const sharedKeys = { current: new Map() };
  let apiMode = 'uncertain';
  let listing = { residencies: [], transitions: [] };
  let refreshCount = 0;
  let uuidCount = 0;
  const api = async (url, init) => {
    apiCalls.push({ url, init });
    if (init?.method === 'POST') {
      postKeys.push(init.headers['Idempotency-Key']);
      if (apiMode === 'uncertain') throw new Error('connection lost');
      const desiredTier = JSON.parse(init.body).desired_tier;
      return transitionResponse({ targetId: 'target-a', model: 'model one', observedTier: desiredTier });
    }
    return listing;
  };
  const handlerForOverview = (rows) => loadActualCardHandler()(
    { id: 'target-a' }, 'model one', sharedKeys, { randomUUID: () => `card-key-${++uuidCount}` },
    requestRuntimeTransition, recoverRuntimeTransition, retireSettledRequestKeys, rows, api,
    () => {}, (message) => messages.push(message), () => {}, () => { refreshCount++; },
  );
  await handlerForOverview([])('hot_vram');
  const originalLoadKey = postKeys[0];
  assert.ok(originalLoadKey);
  await handlerForOverview([{ id: 'wrong-key-row', idempotency_key: 'some-other-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'succeeded' }])('hot_vram');
  assert.equal(postKeys.length, 1, 'an uncertain held key must use read-only GET recovery, not another POST');
  assert.equal(apiCalls.at(-1).url, '/admin/api/residency');
  assert.equal(messages.at(-1).includes(originalLoadKey), true);
  assert.equal(refreshCount, 2, 'actual card handler refreshes after POST and lookup errors');

  apiMode = 'projection';
  const terminalLoad = { id: 'load-history', idempotency_key: originalLoadKey, target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'succeeded', observed_tier: 'hot_vram' };
  await handlerForOverview([terminalLoad])('cold_disk');
  assert.notEqual(postKeys[1], originalLoadKey, 'a terminal poll result retires the old load key before a later unload action');
  await handlerForOverview([terminalLoad])('hot_vram');
  assert.notEqual(postKeys[2], originalLoadKey, 'a subsequent load after terminal history receives a fresh identity');
  assert.equal(postKeys.length, 3);
  assert.equal(refreshCount, 4);

  const failedRequestKeyMap = { current: new Map() };
  const failedRequestPosts = [];
  let failedRequestGets = 0;
  const failedHistory = { id: 'failed-load', idempotency_key: 'pending-failure-key', target_id: 'target-a', model: 'model one', to_tier: 'hot_vram', status: 'failed', error: 'controller operation failed' };
  const failedApi = async (url, init) => {
    if (init?.method === 'POST') {
      failedRequestPosts.push(init.headers['Idempotency-Key']);
      return transitionResponse({
        targetId: 'target-a', model: 'model one', observedTier: 'cold_disk',
        transition: failedHistory,
      });
    }
    failedRequestGets++;
    return { residencies: [{ target_id: 'target-a', model: 'model one', observed_tier: 'cold_disk' }], transitions: [failedHistory] };
  };
  const failedHandlerForOverview = (rows) => loadActualCardHandler()(
    { id: 'target-a' }, 'model one', failedRequestKeyMap, { randomUUID: () => 'pending-failure-key' },
    requestRuntimeTransition, recoverRuntimeTransition, retireSettledRequestKeys, rows, failedApi,
    () => {}, (message) => messages.push(message), () => {}, () => {},
  );
  await failedHandlerForOverview([])('hot_vram');
  assert.equal(failedRequestPosts.length, 1);
  assert.equal(failedRequestKeyMap.current.get(JSON.stringify(['target-a', 'model one', 'hot_vram'])), 'pending-failure-key',
    'an original failed status must retain the possibly-effectful request identity');
  assert.match(messages.at(-1), /does not prove no runtime effect occurred/i);
  await failedHandlerForOverview([failedHistory])('hot_vram');
  assert.equal(failedRequestPosts.length, 1, 'a held failed key must never be replayed with another POST');
  assert.equal(failedRequestGets, 1, 'a held failed key is checked through read-only GET');
  assert.equal(failedRequestKeyMap.current.get(JSON.stringify(['target-a', 'model one', 'hot_vram'])), 'pending-failure-key');
  assert.match(messages.at(-1), /no new POST will be sent/i);
}

verifyCardWiring();
await verifyActualHelper();
console.log('runtime control request verification passed');
