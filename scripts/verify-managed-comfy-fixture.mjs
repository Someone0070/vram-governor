#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { isAbsolute, relative, resolve, sep } from 'node:path';

const originalPath = 'internal/workloads/managed_comfy_test.go';
const baselinePath = '.unlazy/fleet-residency-v2/managed-comfy-fixture-full-baseline.json';
const maxSourceBytes = 1 << 20;
const maxBaselineBytes = 1 << 15;
const maxScriptBytes = 1 << 18;
const maxOutputBytes = 16 << 20;
const runtimeTimeoutMs = 120_000;
const originalBytes = 10_946;
const originalSHA256 = 'fac1bdec040004ac32e946f2b6f1bc70acb82feac6da653bcf0dfd174ac9c5fc';
const baselineBytes = 12_044;
const baselineSHA256 = '4c8b24b5dad77c9fdd1dc09b0b8aeae7e026b2915d97555e8388f6ce48eee048';
const expectedTests = [
  'TestManagedComfyLifecycle',
  'TestManagedComfyRejectsAmbiguousState',
  'TestTargetSpecificDisruptionSelectsManagedComfy',
  'TestRuntimeProtocolChangesPlanHash',
  'TestManagedComfyChunksRequireManagedProtocolAndAggregateRequirements',
];

const insertedCase = '\tcase r.Method == http.MethodGet && r.URL.Path == "/object_info":\n'
  + '\t\t_, _ = w.Write([]byte(`{"ChunkedVideo":{"input":{"required":{},"optional":{}},"output":["VIDEO"],"output_name":["video"]},"Video":{"input":{"required":{"ckpt_name":[["video.safetensors"]]},"optional":{}},"output":["VIDEO"],"output_name":["video"]},"LoaderA":{"input":{"required":{"ckpt_name":[["a.safetensors"]]},"optional":{}},"output":["MODEL"],"output_name":["model"]},"LoaderB":{"input":{"required":{"unet_name":[["b.safetensors"]]},"optional":{}},"output":["MODEL"],"output_name":["model"]}}`))\n';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function boundedRegularRead(root, relativePath, byteLimit) {
  invariant(typeof relativePath === 'string' && !isAbsolute(relativePath), `absolute path rejected: ${relativePath}`);
  const fullPath = resolve(root, relativePath);
  const rel = relative(root, fullPath);
  invariant(rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel), `path escaped the repository: ${relativePath}`);
  const info = lstatSync(fullPath);
  invariant(info.isFile() && !info.isSymbolicLink(), `expected a regular, non-link file: ${relativePath}`);
  invariant(info.nlink === 1, `expected a single-link file: ${relativePath}`);
  invariant(info.size <= byteLimit, `file exceeds the ${byteLimit}-byte read bound: ${relativePath}`);
  const bytes = readFileSync(fullPath);
  invariant(bytes.length === info.size && bytes.length <= byteLimit, `file changed or exceeded its read bound: ${relativePath}`);
  return bytes;
}

function decodeUTF8(bytes, label) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new Error(`${label} is not valid UTF-8`);
  }
}

function authenticateBaseline(root) {
  const bytes = boundedRegularRead(root, baselinePath, maxBaselineBytes);
  invariant(bytes.length === baselineBytes, 'DATAONLY baseline byte count changed');
  invariant(sha256(bytes) === baselineSHA256, 'DATAONLY baseline SHA256 changed');
  const data = JSON.parse(decodeUTF8(bytes, 'DATAONLY baseline'));
  invariant(data.kind === 'DATAONLY never execute or import embedded source', 'baseline is not marked DATAONLY');
  invariant(Array.isArray(data.files) && data.files.length === 1, 'baseline file inventory changed');
  const record = data.files[0];
  invariant(record.path === originalPath && record.bytes === originalBytes && record.sha256 === originalSHA256, 'baseline original identity changed');
  invariant(typeof record.utf8 === 'string', 'baseline source payload is missing');
  const original = Buffer.from(record.utf8, 'utf8');
  invariant(original.length === originalBytes && sha256(original) === originalSHA256, 'embedded DATAONLY original failed its own authentication');
  return original;
}

function testInventory(source) {
  const names = [...source.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\) \{$/gm)].map((match) => match[1]);
  invariant(JSON.stringify(names) === JSON.stringify(expectedTests), 'original test declarations differ from the authenticated five-test inventory');
  return names;
}

function decodeFixtureSchema(caseText) {
  const match = caseText.match(/w\.Write\(\[\]byte\(`([\s\S]*)`\)\)/);
  invariant(match, 'inserted route must write one static JSON object');
  return JSON.parse(match[1]);
}

function validateSchema(schema) {
  const expectedNames = ['ChunkedVideo', 'Video', 'LoaderA', 'LoaderB'];
  invariant(JSON.stringify(Object.keys(schema)) === JSON.stringify(expectedNames), 'fixture schema class inventory changed');
  const definitions = {
    ChunkedVideo: { required: {}, output: ['VIDEO'], outputName: ['video'] },
    Video: { required: { ckpt_name: [['video.safetensors']] }, output: ['VIDEO'], outputName: ['video'] },
    LoaderA: { required: { ckpt_name: [['a.safetensors']] }, output: ['MODEL'], outputName: ['model'] },
    LoaderB: { required: { unet_name: [['b.safetensors']] }, output: ['MODEL'], outputName: ['model'] },
  };
  for (const name of expectedNames) {
    const actual = schema[name];
    const expected = definitions[name];
    invariant(actual && JSON.stringify(Object.keys(actual)) === JSON.stringify(['input', 'output', 'output_name']), `${name} schema fields changed`);
    invariant(actual.input && JSON.stringify(Object.keys(actual.input)) === JSON.stringify(['required', 'optional']), `${name} input groups changed`);
    invariant(JSON.stringify(actual.input.required) === JSON.stringify(expected.required), `${name} required inputs or model enum changed`);
    invariant(JSON.stringify(actual.input.optional) === '{}', `${name} optional inputs changed`);
    invariant(JSON.stringify(actual.output) === JSON.stringify(expected.output), `${name} output definition changed`);
    invariant(JSON.stringify(actual.output_name) === JSON.stringify(expected.outputName), `${name} output name changed`);
  }
}

function checkSourceCandidate(source, original) {
  const occurrences = source.split(insertedCase).length - 1;
  invariant(occurrences === 1, 'expected exactly one bounded object_info case');
  const routeAt = source.indexOf(insertedCase);
  const authAt = source.indexOf('if f.authorization != "" && r.Header.Get("Authorization") != f.authorization {');
  const switchAt = source.indexOf('\tswitch {', authAt);
  invariant(authAt >= 0 && switchAt > authAt && routeAt > switchAt, 'authorization must precede object_info switch dispatch');
  invariant(source.indexOf('/object_info', routeAt + insertedCase.length) === -1, 'unexpected additional object_info fixture route');
  const stripped = source.slice(0, routeAt) + source.slice(routeAt + insertedCase.length);
  invariant(stripped === original.toString('utf8'), 'original managed Comfy test source changed outside the inserted case');
  testInventory(stripped);
  validateSchema(decodeFixtureSchema(insertedCase));
}

function mustReject(action, message) {
  let rejected = false;
  try { action(); } catch { rejected = true; }
  invariant(rejected, message);
}

function mustRejectWithMessage(action, expectedMessage, message) {
  let actualMessage = null;
  try { action(); } catch (error) { actualMessage = error instanceof Error ? error.message : null; }
  invariant(actualMessage === expectedMessage, message);
}

function verifySourceControls(source, original) {
  checkSourceCandidate(source, original);

  mustReject(() => checkSourceCandidate(source.replace(insertedCase, ''), original), 'missing-route mutation was accepted');
  const wrongModel = source.replace('video.safetensors', 'wrong.safetensors');
  mustReject(() => checkSourceCandidate(wrongModel, original), 'wrong-model mutation was accepted');
  const routeAt = source.indexOf(insertedCase);
  const authAt = source.indexOf('if f.authorization != "" && r.Header.Get("Authorization") != f.authorization {');
  const authBlockStart = source.lastIndexOf('\tw.Header().Set("Content-Type", "application/json")', authAt);
  const routeBeforeAuth = source.slice(0, authBlockStart) + insertedCase + source.slice(authBlockStart, routeAt) + source.slice(routeAt + insertedCase.length);
  mustReject(() => checkSourceCandidate(routeBeforeAuth, original), 'route-before-authorization mutation was accepted');
  const preservationMutation = source.replace('fixture.starts != 2', 'fixture.starts != 3');
  mustReject(() => checkSourceCandidate(preservationMutation, original), 'original-source preservation mutation was accepted');
}

function verifyVerifierPredicates(self) {
  invariant(self.includes("const { spawnSync } = await import('node:child_process');"), 'runtime process import is missing');
  invariant(self.includes("if (mode === 'source-only') {"), 'source-only mode branch is missing');
  const sourceOnlyControlCall = "verifySource(root);\n  verifyInventoryControls();\n  if (mode === 'source-only') {";
  invariant(self.includes(sourceOnlyControlCall), 'source-only mode does not run parser controls before its mode boundary');
  const controlsStart = self.indexOf('function verifyInventoryControls() {');
  const controlsEnd = self.indexOf('\nasync function verifyRuntime', controlsStart);
  const controls = self.slice(controlsStart, controlsEnd);
  invariant(controlsStart >= 0 && controlsEnd > controlsStart && controls.includes('parseRuntimeInventory(positive);') && controls.indexOf('parseRuntimeInventory(positive);') < controls.indexOf('const positiveLines'), 'parser controls do not accept the realistic positive transcript first');
  const invocation = self.match(/const result = spawnSync\('go', \[([^\]]+)\], \{([\s\S]*?)\n  \}\);/);
  invariant(invocation && invocation[1].includes("'test'") && invocation[1].includes("'-json'") && invocation[1].includes("'-count=1'") && invocation[1].includes("'-timeout=90s'") && invocation[1].includes("'./internal/workloads'") && invocation[1].includes("'-run'") && invocation[2].includes('timeout: runtimeTimeoutMs') && invocation[2].includes('maxBuffer: maxOutputBytes'), 'bounded uncached selected Go test invocation changed');
  invariant(self.includes('result.stderr') && self.includes('Buffer.byteLength(result.stdout') && self.includes('Buffer.byteLength(result.stderr'), 'runtime stdout and stderr policy is missing');
  const parserStart = self.lastIndexOf('\nfunction parseRuntimeInventory(') + 1;
  const parserEnd = self.indexOf('\nfunction verifyInventoryControls', parserStart);
  const parser = self.slice(parserStart, parserEnd);
  invariant(parser.includes('invariant(event.Package === targetPackage,'), 'test and output package ownership check is missing');
  invariant(parser.includes('packageStarted && packagePasses === 1 && sawPassOutput && sawPackageSummary && terminal'), 'terminal package PASS and summary check is missing');
  invariant(parser.includes('isPackageSummary(event.Output)'), 'target package summary validation is missing');
  const testOutputGuard = "invariant(event.Output !== 'PASS\\n' && !isPackageSummary(event.Output), 'PASS or package summary output must be owned by the package');";
  invariant(parser.includes(testOutputGuard), 'test-owned package summary output guard is missing');
  const testOutputStringGuard = "invariant(typeof event.Output === 'string', 'test output must be a string');";
  invariant(parser.includes(testOutputStringGuard), 'test-owned output string guard is missing');
  invariant(controls.includes("Output: '    fixture log\\n'"), 'positive transcript lacks realistic active test-owned output');
  invariant(controls.includes('missing package summary') && controls.includes('duplicate package summary') && controls.includes('early package summary') && controls.includes('foreign package summary') && controls.includes('test-owned package summary') && controls.includes('malformed package summary duration') && controls.includes('out-of-bounds package summary duration'), 'package summary negative controls are incomplete');
  invariant(controls.includes("['missing', 'null', 'numeric', 'object', 'array']") && controls.includes('malformedTestOutputs'), 'malformed test-owned output controls are incomplete');
}

function verifyVerifierSourceControls(self) {
  verifyVerifierPredicates(self);
  const runtimeStart = self.lastIndexOf('\nasync function verifyRuntime(') + 1;
  const mainStart = self.indexOf('\nasync function main()', runtimeStart);
  const runtime = self.slice(runtimeStart, mainStart);
  const withoutCount = runtime.replace("'-count=1', ", '');
  mustReject(() => verifyVerifierPredicates(self.slice(0, runtimeStart) + withoutCount + self.slice(mainStart)), 'uncached invocation omission mutation was accepted');
  const mainEnd = self.indexOf('\n}\n\nmain().catch', mainStart);
  const main = self.slice(mainStart, mainEnd);
  const withoutControls = main.replace("verifySource(root);\n  verifyInventoryControls();\n  if (mode === 'source-only') {", "verifySource(root);\n  if (mode === 'source-only') {");
  mustReject(() => verifyVerifierPredicates(self.slice(0, mainStart) + withoutControls + self.slice(mainEnd)), 'source-only parser-control omission mutation was accepted');
  const parserStart = self.lastIndexOf('\nfunction parseRuntimeInventory(') + 1;
  const controlsStart = self.indexOf('\nfunction verifyInventoryControls', parserStart);
  const parser = self.slice(parserStart, controlsStart);
  const withoutTerminal = parser.replace('invariant(packageStarted && packagePasses === 1 && sawPassOutput && sawPackageSummary && terminal,', 'invariant(packageStarted && packagePasses === 1 && sawPassOutput && sawPackageSummary,');
  mustReject(() => verifyVerifierPredicates(self.slice(0, parserStart) + withoutTerminal + self.slice(controlsStart)), 'terminal-order predicate omission mutation was accepted');
  const testOutputGuard = "event.Output !== 'PASS\\n' && !isPackageSummary(event.Output)";
  invariant(parser.split(testOutputGuard).length - 1 === 1, 'test-output summary guard is not unique');
  const withoutTestSummaryGuard = parser.replace(testOutputGuard, "event.Output !== 'PASS\\n'");
  mustReject(() => verifyVerifierPredicates(self.slice(0, parserStart) + withoutTestSummaryGuard + self.slice(controlsStart)), 'test-output summary guard omission mutation was accepted');
  const testOutputStringGuard = "invariant(typeof event.Output === 'string', 'test output must be a string');";
  invariant(parser.split(testOutputStringGuard).length - 1 === 1, 'test-output string guard is not unique');
  const withoutTestOutputStringGuard = parser.replace(testOutputStringGuard, '');
  mustReject(() => verifyVerifierPredicates(self.slice(0, parserStart) + withoutTestOutputStringGuard + self.slice(controlsStart)), 'test-output string guard omission mutation was accepted');
}

function verifyOwnEffects(root) {
  const bytes = boundedRegularRead(root, 'scripts/verify-managed-comfy-fixture.mjs', maxScriptBytes);
  const self = decodeUTF8(bytes, 'verifier source');
  invariant(self.startsWith('#!/usr/bin/env node\n'), 'verifier must use the Node entry point');
  invariant(!/^import .* from 'node:(?:child_process|net|http|https|os|url)'/m.test(self), 'verifier has an eager process or network import');
  invariant(!/\b(?:writeFileSync|mkdtempSync|unlinkSync|rmdirSync|mkdirSync|rmSync|execSync)\s*\(/.test(self), 'source verifier contains a direct write, temp, or process effect');
  invariant(self.includes("const { spawnSync } = await import('node:child_process');") && self.includes('if (mode === \'source-only\') {'), 'runtime execution boundary is missing');
  invariant(self.indexOf("if (mode === 'source-only') {") < self.indexOf('await verifyRuntime(root, expectedTests);'), 'source-only branch does not precede runtime execution');
  verifyVerifierSourceControls(self);
}

function verifySource(root) {
  verifyOwnEffects(root);
  const original = authenticateBaseline(root);
  const sourceBytes = boundedRegularRead(root, originalPath, maxSourceBytes);
  const source = decodeUTF8(sourceBytes, originalPath);
  invariant(sourceBytes.length <= originalBytes + 2048, 'managed Comfy test source exceeded the bounded insertion allowance');
  verifySourceControls(source, original);
}

const targetPackage = 'vram-governor/internal/workloads';
const maxPackageDurationSeconds = 90;

function isPackageSummary(output) {
  if (typeof output !== 'string') return false;
  const escapedPackage = targetPackage.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const match = output.match(new RegExp(`^ok[\\t ]+${escapedPackage}[\\t ]+(\\d+(?:\\.\\d+)?)s\\n$`));
  if (!match) return false;
  const duration = Number(match[1]);
  return Number.isFinite(duration) && duration >= 0 && duration <= maxPackageDurationSeconds;
}

function inventoryFixture(names = expectedTests, status = 0) {
  const events = [{ Action: 'start', Package: targetPackage }];
  for (let index = 0; index < names.length; index++) {
    const name = names[index];
    events.push({ Action: 'run', Package: targetPackage, Test: name });
    if (index === 0) {
      events.push({ Action: 'output', Package: targetPackage, Test: name, Output: '    fixture log\n' });
      events.push(
        { Action: 'run', Package: targetPackage, Test: `${name}/nested` },
        { Action: 'run', Package: targetPackage, Test: `${name}/nested/grandchild` },
        { Action: 'pass', Package: targetPackage, Test: `${name}/nested/grandchild` },
        { Action: 'pass', Package: targetPackage, Test: `${name}/nested` },
      );
    }
    events.push({ Action: 'pass', Package: targetPackage, Test: name });
  }
  events.push(
    { Action: 'output', Package: targetPackage, Output: 'PASS\n' },
    { Action: 'output', Package: targetPackage, Output: `ok  ${targetPackage}\t0.123s\n` },
    { Action: 'pass', Package: targetPackage },
  );
  return { status, signal: null, error: null, output: events.map((event) => JSON.stringify(event)).join('\n') };
}

function parseRuntimeInventory(result, expected = expectedTests) {
  invariant(result.status === 0 && result.signal == null && result.error == null, 'Go test process did not exit successfully without a signal');
  invariant(Buffer.byteLength(result.output, 'utf8') <= maxOutputBytes, 'Go test transcript exceeded the output bound');
  const lines = result.output.split(/\r?\n/).filter((line) => line.length > 0);
  let nextParent = 0;
  let active = null;
  let packagePasses = 0;
  let sawPassOutput = false;
  let sawPackageSummary = false;
  let packageStarted = false;
  let terminal = false;
  const childStates = new Map();

  for (const line of lines) {
    invariant(!terminal, 'Go emitted an event after the terminal package PASS');
    let event;
    try { event = JSON.parse(line); } catch { throw new Error(`malformed go test JSON event: ${line.slice(0, 240)}`); }
    invariant(event && typeof event === 'object' && !Array.isArray(event), 'go test emitted a non-object event');
    invariant(event.Package === targetPackage, `missing or foreign Go package event: ${event.Package}`);
    invariant(typeof event.Action === 'string' && event.Action.length > 0, 'Go event action is missing or malformed');
    if (event.Action === 'start' && event.Test === undefined) {
      invariant(!packageStarted && nextParent === 0 && active === null && lines.indexOf(line) === 0, 'package start must occur exactly once before tests');
      packageStarted = true;
      continue;
    }
    invariant(packageStarted, 'Go test event arrived before package start');
    if (event.Action === 'pass' && event.Test === undefined) {
      invariant(active === null && nextParent === expected.length && sawPassOutput && sawPackageSummary, 'package PASS arrived before all tests, PASS output, or package summary');
      packagePasses++;
      terminal = true;
      continue;
    }
    if (event.Action === 'output' && event.Test === undefined) {
      invariant(typeof event.Output === 'string' && nextParent === expected.length && active === null, 'package output is foreign, unexpected, or precedes completed tests');
      if (event.Output === 'PASS\n') {
        invariant(!sawPassOutput && !sawPackageSummary, 'duplicate or late package PASS output');
        sawPassOutput = true;
      } else {
        invariant(sawPassOutput && !sawPackageSummary && isPackageSummary(event.Output), 'package summary is early, duplicate, malformed, cached, foreign, or out of bounds');
        sawPackageSummary = true;
      }
      continue;
    }
    invariant(typeof event.Test === 'string' && event.Test.length > 0, 'test event Test must be a nonempty string');
    const parts = event.Test.split('/');
    invariant(parts.every((part) => part.length > 0), `malformed Go test name: ${event.Test}`);
    const rootName = parts[0];
    invariant(expected.includes(rootName), `foreign Go test event: ${event.Test}`);

    if (event.Action === 'run') {
      if (parts.length === 1) {
        invariant(active === null && rootName === expected[nextParent], `missing, duplicate, foreign, or reordered parent RUN: ${event.Test}`);
        active = { name: rootName, passed: false, childRuns: new Set(), childPasses: new Set() };
      } else {
        invariant(active && active.name === rootName && !active.passed, `foreign or late nested RUN: ${event.Test}`);
        const parentPath = parts.slice(0, -1).join('/');
        invariant(parts.length === 2 || childStates.get(parentPath) === 'run', `nested RUN lacks an active parent: ${event.Test}`);
        invariant(!childStates.has(event.Test), `duplicate nested RUN: ${event.Test}`);
        childStates.set(event.Test, 'run');
        if (parts.length === 2) active.childRuns.add(event.Test);
      }
      continue;
    }
    if (event.Action === 'pass') {
      if (parts.length === 1) {
        invariant(active && active.name === rootName && !active.passed, `unexpected, duplicate, or reordered parent PASS: ${event.Test}`);
        for (const child of active.childRuns) invariant(active.childPasses.has(child), `nested test lacks PASS terminal: ${child}`);
        active.passed = true;
        active = null;
        nextParent++;
      } else {
        invariant(active && active.name === rootName && childStates.get(event.Test) === 'run', `nested PASS lacks a matching RUN: ${event.Test}`);
        for (const [child, state] of childStates) {
          if (child.startsWith(`${event.Test}/`)) invariant(state === 'pass', `nested test lacks PASS terminal: ${child}`);
        }
        invariant(!active.childPasses.has(event.Test), `duplicate nested PASS: ${event.Test}`);
        if (parts.length === 2) active.childPasses.add(event.Test);
        childStates.set(event.Test, 'pass');
      }
      continue;
    }
    invariant(event.Action !== 'skip' && event.Action !== 'fail', `Go test ${event.Action}: ${event.Test}`);
    if (event.Action === 'output') {
      invariant(active && active.name === rootName, `test output has no active parent: ${event.Test}`);
      if (parts.length > 1) invariant(childStates.get(event.Test) === 'run', `nested output has no active subtest: ${event.Test}`);
      invariant(typeof event.Output === 'string', 'test output must be a string');
      invariant(event.Output !== 'PASS\n' && !isPackageSummary(event.Output), 'PASS or package summary output must be owned by the package');
      continue;
    }
    invariant(false, `unexpected test action ${event.Action}: ${event.Test}`);
  }
  invariant(active === null && nextParent === expected.length, 'Go transcript omitted or left an incomplete five-test inventory');
  invariant(packageStarted && packagePasses === 1 && sawPassOutput && sawPackageSummary && terminal, 'Go transcript lacks its package start, PASS output, package summary, or terminal package PASS');
}

function verifyInventoryControls() {
  const positive = inventoryFixture();
  parseRuntimeInventory(positive);
  const positiveLines = positive.output.split('\n').map((line) => JSON.parse(line));
  const reject = (events, message, overrides = {}) => mustReject(() => parseRuntimeInventory({ status: 0, signal: null, error: null, output: events.map((event) => JSON.stringify(event)).join('\n'), ...overrides }), message);
  reject(positiveLines.filter((event) => !(event.Action === 'run' && event.Test === expectedTests[0])), 'missing RUN transcript mutation was accepted');
  reject(positiveLines.map((event) => event.Action === 'pass' && event.Test === expectedTests[0] ? { ...event, Action: 'skip' } : event), 'SKIP transcript mutation was accepted');
  reject([...positiveLines.slice(0, 2), ...positiveLines.slice(0, 2), ...positiveLines.slice(2)], 'duplicate RUN transcript mutation was accepted');
  reject([...positiveLines, { Action: 'run', Test: 'TestForeign' }], 'foreign test transcript mutation was accepted');
  reject(positiveLines, 'nonzero runtime status mutation was accepted', { status: 1 });
  mustReject(() => parseRuntimeInventory({ status: 0, signal: null, error: null, output: `${positive.output}\n{bad json` }), 'malformed JSON mutation was accepted');
  reject([...positiveLines.slice(0, -1), { Action: 'pass', Package: targetPackage }, ...positiveLines.slice(-1)], 'early package terminal mutation was accepted');
  reject([...positiveLines, { Action: 'start', Package: targetPackage }], 'event after package terminal mutation was accepted');
  reject(positiveLines.map((event) => event.Test === `${expectedTests[0]}/nested` && event.Action === 'pass' ? { ...event, Action: 'fail' } : event), 'nested failure mutation was accepted');
  reject(positiveLines.filter((event) => !(event.Test === `${expectedTests[0]}/nested` && event.Action === 'pass')), 'missing nested terminal mutation was accepted');
  reject([...positiveLines.slice(0, 2), { Action: 'pass', Package: targetPackage, Test: `${expectedTests[0]}/orphan` }, ...positiveLines.slice(2)], 'orphan nested PASS mutation was accepted');
  reject(positiveLines.map((event) => event.Action === 'output' && event.Output === 'PASS\n' ? { ...event, Package: 'foreign/pkg' } : event), 'foreign PASS output mutation was accepted');
  reject(positiveLines.map((event) => event.Test === expectedTests[0] && event.Action === 'run' ? { ...event, Package: 'foreign/pkg' } : event), 'foreign test package mutation was accepted');
  reject(positiveLines.map((event) => event.Test === expectedTests[0] && event.Action === 'run' ? { ...event, Test: '' } : event), 'empty Test mutation was accepted');
  const summaryIndex = positiveLines.findIndex((event) => event.Action === 'output' && event.Output?.startsWith('ok'));
  reject(positiveLines.filter((_, index) => index !== summaryIndex), 'missing package summary mutation was accepted');
  reject([...positiveLines.slice(0, summaryIndex + 1), positiveLines[summaryIndex], ...positiveLines.slice(summaryIndex + 1)], 'duplicate package summary mutation was accepted');
  reject([...positiveLines.slice(0, summaryIndex - 1), positiveLines[summaryIndex], ...positiveLines.slice(summaryIndex - 1)], 'early package summary mutation was accepted');
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Package: 'foreign/pkg' } : event), 'foreign package summary mutation was accepted');
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Output: 'ok  foreign/pkg\t0.123s\n' } : event), 'foreign package summary payload mutation was accepted');
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Output: `ok  ${targetPackage}\t(cached)\n` } : event), 'cached package summary mutation was accepted');
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Output: `ok  ${targetPackage}\tnot-a-duration\n` } : event), 'malformed package summary duration mutation was accepted');
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Output: `ok  ${targetPackage}\t90.001s\n` } : event), 'out-of-bounds package summary duration mutation was accepted');
  const firstParentRun = positiveLines.findIndex((event) => event.Action === 'run' && event.Test === expectedTests[0]);
  const testOwnedSummary = [
    ...positiveLines.slice(0, firstParentRun + 1),
    { Action: 'output', Package: targetPackage, Test: expectedTests[0], Output: `ok  ${targetPackage}\t0.123s\n` },
    ...positiveLines.slice(firstParentRun + 1),
  ];
  mustRejectWithMessage(
    () => parseRuntimeInventory({ ...positive, output: testOwnedSummary.map((event) => JSON.stringify(event)).join('\n') }),
    'PASS or package summary output must be owned by the package',
    'test-owned package summary did not reach the specific ownership guard',
  );
  const malformedTestOutputs = [
    { label: 'missing', event: { Action: 'output', Package: targetPackage, Test: expectedTests[0] } },
    { label: 'null', event: { Action: 'output', Package: targetPackage, Test: expectedTests[0], Output: null } },
    { label: 'numeric', event: { Action: 'output', Package: targetPackage, Test: expectedTests[0], Output: 7 } },
    { label: 'object', event: { Action: 'output', Package: targetPackage, Test: expectedTests[0], Output: {} } },
    { label: 'array', event: { Action: 'output', Package: targetPackage, Test: expectedTests[0], Output: [] } },
  ];
  invariant(JSON.stringify(malformedTestOutputs.map(({ label }) => label)) === JSON.stringify(['missing', 'null', 'numeric', 'object', 'array']), 'malformed test-output cases changed');
  for (const { label, event } of malformedTestOutputs) {
    const events = [...positiveLines.slice(0, firstParentRun + 1), event, ...positiveLines.slice(firstParentRun + 1)];
    mustRejectWithMessage(
      () => parseRuntimeInventory({ ...positive, output: events.map((item) => JSON.stringify(item)).join('\n') }),
      'test output must be a string',
      `test-owned ${label} output did not reach the specific malformed-output guard`,
    );
  }
  reject(positiveLines.map((event, index) => index === summaryIndex ? { ...event, Output: '# compiler error\n' } : event), 'compiler or error output mutation was accepted');
  reject([...positiveLines, { Action: 'output', Package: targetPackage, Output: `ok  ${targetPackage}\t0.123s\n` }], 'post-terminal package summary mutation was accepted');
  mustReject(() => parseRuntimeInventory({ status: 0, signal: 'SIGTERM', error: null, output: positive.output }), 'signal result mutation was accepted');
  mustReject(() => parseRuntimeInventory({ status: null, signal: null, error: new Error('spawn failed'), output: positive.output }), 'process error mutation was accepted');
}

async function verifyRuntime(root, expected) {
  const { spawnSync } = await import('node:child_process');
  const runtimeEnv = { ...process.env, GOTOOLCHAIN: 'local' };
  const version = spawnSync('go', ['version'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000,
    maxBuffer: 4096,
    windowsHide: true,
    env: runtimeEnv,
  });
  invariant(version.status === 0 && version.signal == null && version.error == null && /^go version go1\.23\.4\b/.test(version.stdout ?? ''), 'runtime mode requires the cached Go 1.23.4 toolchain');
  const pattern = `^(${expected.join('|')})$`;
  const result = spawnSync('go', ['test', '-json', '-count=1', '-timeout=90s', './internal/workloads', '-run', pattern], {
    cwd: root,
    encoding: 'utf8',
    timeout: runtimeTimeoutMs,
    maxBuffer: maxOutputBytes,
    windowsHide: true,
    env: runtimeEnv,
  });
  if (result.error) throw new Error(`Go test could not complete: ${result.error.message}`);
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  invariant(Buffer.byteLength(stdout, 'utf8') + Buffer.byteLength(stderr, 'utf8') <= maxOutputBytes, 'Go test stdout and stderr exceeded the combined output bound');
  invariant(stderr.length === 0, `Go test wrote unexpected stderr: ${stderr.slice(0, 240)}`);
  parseRuntimeInventory({ status: result.status, signal: result.signal, error: result.error, output: stdout }, expected);
}

async function main() {
  const modeArg = process.argv[2];
  invariant((modeArg === '--mode=source-only' || modeArg === '--mode=runtime') && process.argv.length === 3, 'usage: node scripts/verify-managed-comfy-fixture.mjs --mode=source-only|runtime');
  const mode = modeArg.slice('--mode='.length);
  const root = process.cwd();
  verifySource(root);
  verifyInventoryControls();
  if (mode === 'source-only') {
    process.stdout.write('managed Comfy fixture source preservation passed\n');
    return;
  }
  await verifyRuntime(root, expectedTests);
  process.stdout.write('managed Comfy fixture regression verification passed\n');
}

main().catch((error) => {
  process.stderr.write(`managed Comfy fixture verification failed: ${error.message}\n`);
  process.exitCode = 1;
});
