#!/usr/bin/env node
import { mkdtempSync, readFileSync, readdirSync, rmdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';

const requiredTests = [
  'TestManagedComfySafeBoundaryAndResume',
  'TestManagedComfyYieldAndResume',
  'TestManagedComfyCheckpointReferenceIsFreshPerEpoch',
  'TestManagedComfyRejectsLegacyCheckpointWithoutFreshReference',
  'TestManagedComfyCancelConfirmsBackendStop',
  'TestManagedComfyCancelDoesNotInterruptExactRunningPrompt',
  'TestManagedComfyCancelDuringAcceptancePreservesUncertainCustody',
  'TestManagedComfyPayloadMismatchCannotResumeIdempotencyKey',
  'TestManagedComfyChunkCommitFailureIsNotAcknowledgedOrRepeated',
  'TestManagedComfyLostPromptResponseIsNeverResubmitted',
  'TestManagedComfyAcceptedThenServerErrorIsNeverResubmitted',
  'TestManagedComfySubmissionIntentFaultPreventsPromptPost',
  'TestManagedComfyCheckpointCommitFailureStaysUncertain',
  'TestManagedComfyResumePersistFailureRollsBackMemory',
  'TestManagedComfyCancelCommitFailureIsNotAcknowledged',
  'TestManagedComfyStopTimeoutStaysUncertain',
  'TestManagedComfyMalformedQueueOrHistoryCannotConfirmCancel',
  'TestManagedComfyRejectsCorruptDurableSnapshot',
  'TestManagedComfyRejectsConcurrentStateOwner',
  'TestManagedComfyStateOwnerLockReleasesAfterAbruptExit',
  'TestManagedComfyStateBudgetCannotAcknowledgeUnrecoverableSnapshot',
  'TestManagedComfyNearQuotaAcceptedSnapshotRecoversAndDeduplicates',
  'TestManagedComfyRestartRecoveryHeadroomRequired',
  'TestManagedComfyRestartFailsUnconfirmedRun',
  'TestManagedComfyRequiresAuthorization',
  'TestComfyDiscoveryObjectInfoPreservesSchema',
  'TestComfyDiscoverySystemStatsPreservesDeviceStats',
  'TestComfyDiscoveryRequiresAuthorization',
  'TestComfyDiscoveryRejectsQueryBodyAndUnsupportedRoutes',
  'TestComfyDiscoveryUsesFixedBackendPathAndIsolatesCredentials',
  'TestComfyDiscoveryRejectsBaseURLComponents',
  'TestComfyDiscoveryRejectsRedirectWithoutFollowing',
  'TestComfyDiscoveryRejectsOversizedBodies',
  'TestComfyDiscoveryRejectsInvalidJSON',
  'TestComfyDiscoveryRejectsNon2xx',
  'TestComfyDiscoveryUsesBoundedRequestContext',
  'TestComfyDiscoveryHonorsParentDeadline',
  'TestComfyDiscoveryLeavesSharedClientUnchanged',
];

const mutantTest = 'TestComfyDiscoveryRequiresAuthorization';
const mutantMarker = 'COMFY_DISCOVERY_AUTH_MUTANT_ASSERTION';

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function parseInventory(result, expected = requiredTests) {
  invariant(result.status === 0 && result.signal == null && result.error == null, 'Go inventory command did not exit successfully');
  const lines = result.output.split(/\r?\n/);
  let next = 0;
  let active = null;
  let sawPassSummary = false;
  let sawPackageSummary = false;

  const finishParent = () => {
    invariant(active && active.parentPassed, 'parent test lacks a PASS terminal observation');
    invariant(active.childTerminalIndex === active.childRuns.length, `child terminal inventory incomplete for ${active.name}`);
    active = null;
    next++;
  };

  for (const line of lines) {
    if (line === 'PASS') {
      if (active) finishParent();
      sawPassSummary = true;
      continue;
    }
    if (/^ok\s+\S+\s+(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)s$/.test(line)) {
      if (active) finishParent();
      sawPackageSummary = true;
      continue;
    }

    const trimmed = line.trimStart();
    if (line.startsWith('=== RUN') || /^--- (PASS|FAIL|SKIP):/.test(line)) {
      const run = line.match(/^=== RUN\s+(Test[A-Za-z0-9_]+)(?:\/(\S+))?$/);
      const terminal = line.match(/^--- (PASS|FAIL|SKIP):\s+(Test[A-Za-z0-9_]+)(?:\/(\S+))? \((?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)s\)$/);
      invariant(run || terminal, `malformed Go test observation: ${line}`);
      if (run?.[2]) {
        invariant(active && !active.parentPassed && run[1] === active.name, `foreign or late child RUN: ${line}`);
        invariant(!active.childRuns.includes(`${run[1]}/${run[2]}`), `duplicate child RUN: ${line}`);
        active.childRuns.push(`${run[1]}/${run[2]}`);
        continue;
      }
      if (terminal && !terminal[3]) {
        invariant(terminal[1] === 'PASS' && active?.name === terminal[2] && !active.parentPassed, `parent test failed, skipped, duplicated, or reordered: ${line}`);
        active.parentPassed = true;
        continue;
      }
      if (active) finishParent();
      invariant(run && !run[2], `malformed parent RUN: ${line}`);
      invariant(run[1] === expected[next], `unexpected or reordered parent RUN: ${run[1]}`);
      active = { name: run[1], parentPassed: false, childRuns: [], childTerminalIndex: 0 };
      continue;
    }

    if (trimmed.startsWith('--- PASS:') || trimmed.startsWith('--- FAIL:') || trimmed.startsWith('--- SKIP:')) {
      const indent = line.length - trimmed.length;
      invariant(indent >= 4 && indent <= 16 && indent % 4 === 0, `child terminal indentation is outside the accepted bound: ${line}`);
      const terminal = trimmed.match(/^--- (PASS|FAIL|SKIP):\s+(Test[A-Za-z0-9_]+)\/(\S+) \((?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)s\)$/);
      invariant(terminal && terminal[1] === 'PASS' && active?.parentPassed, `malformed, failed, skipped, or early child terminal: ${line}`);
      const expectedChild = active.childRuns[active.childTerminalIndex];
      invariant(`${terminal[2]}/${terminal[3]}` === expectedChild, `missing, foreign, duplicate, or reordered child terminal: ${line}`);
      active.childTerminalIndex++;
      continue;
    }

    if (line.startsWith('=== RUN') || trimmed.startsWith('--- ')) invariant(false, `malformed test observation: ${line}`);
  }

  invariant(active === null && next === expected.length, 'Go output omitted or left an incomplete required test inventory');
  invariant(sawPassSummary && sawPackageSummary, 'Go output lacks its exact PASS and package summary lines');
  return true;
}

function fixtureResult(events, status = 0) {
  const output = [
    ...events.map((event) => event.kind === 'run'
      ? `=== RUN   ${event.name}`
      : `--- ${event.kind.toUpperCase()}: ${event.name} (0.00s)`),
    'PASS',
    'ok example/internal/comfyharness 0.100s',
  ].join('\n');
  return { status, signal: null, error: null, output };
}

function positiveEvents(expected) {
  return expected.flatMap((name) => [{ kind: 'run', name }, { kind: 'pass', name }]);
}

function nestedChildFixture({
  childRuns = ['sub-a', 'sub-b'],
  childTerminals = [
    { name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.01s' },
    { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' },
  ],
} = {}) {
  const parent = requiredTests[0];
  const lines = [`=== RUN   ${parent}`];
  for (const child of childRuns) lines.push(`=== RUN   ${parent}/${child}`);
  lines.push(`--- PASS: ${parent} (0.03s)`);
  for (const child of childTerminals) lines.push(`${' '.repeat(child.indent)}--- ${child.kind}: ${parent}/${child.name} (${child.duration})`);
  for (const name of requiredTests.slice(1)) lines.push(`=== RUN   ${name}`, `--- PASS: ${name} (0.00s)`);
  lines.push('PASS', 'ok example/internal/comfyharness 0.100s');
  return { status: 0, signal: null, error: null, output: lines.join('\n') };
}

function expectRejected(result, message) {
  let rejected = false;
  try { parseInventory(result); } catch { rejected = true; }
  invariant(rejected, message);
}

function verifyInventoryOracle() {
  const positive = nestedChildFixture();
  invariant(parseInventory(positive), 'real-shaped parent-before-child positive fixture was rejected');
  invariant(parseInventory(fixtureResult(positiveEvents(requiredTests))), 'positive flat inventory fixture was rejected');

  for (const name of requiredTests) {
    const events = positiveEvents(requiredTests);
    const runIndex = events.findIndex((event) => event.kind === 'run' && event.name === name);
    const passIndex = events.findIndex((event) => event.kind === 'pass' && event.name === name);

    const missingRun = events.slice();
    missingRun.splice(runIndex, 1);
    expectRejected(fixtureResult(missingRun), `missing RUN accepted for ${name}`);

    const missingPass = events.slice();
    missingPass.splice(passIndex, 1);
    expectRejected(fixtureResult(missingPass), `missing PASS accepted for ${name}`);

    const skipped = events.slice();
    skipped[passIndex] = { kind: 'skip', name };
    expectRejected(fixtureResult(skipped), `SKIP accepted for ${name}`);

    const failed = events.slice();
    failed[passIndex] = { kind: 'fail', name };
    expectRejected(fixtureResult(failed), `FAIL accepted for ${name}`);

    const duplicateRun = events.slice();
    duplicateRun.splice(runIndex + 1, 0, { kind: 'run', name });
    expectRejected(fixtureResult(duplicateRun), `duplicate RUN accepted for ${name}`);

    const duplicatePass = events.slice();
    duplicatePass.splice(passIndex + 1, 0, { kind: 'pass', name });
    expectRejected(fixtureResult(duplicatePass), `duplicate PASS accepted for ${name}`);
  }

  const reordered = positiveEvents(requiredTests);
  [reordered[0], reordered[2]] = [reordered[2], reordered[0]];
  expectRejected(fixtureResult(reordered), 'reordered inventory accepted');

  const passBeforeRun = positiveEvents(requiredTests);
  [passBeforeRun[0], passBeforeRun[1]] = [passBeforeRun[1], passBeforeRun[0]];
  expectRejected(fixtureResult(passBeforeRun), 'PASS-before-RUN inventory accepted');

  expectRejected(fixtureResult([...positiveEvents(requiredTests), { kind: 'run', name: 'TestForeign' }]), 'foreign test accepted');
  expectRejected({ ...positive, output: positive.output.replace(' (0.00s)', ' unexpected') }, 'malformed terminal line accepted');
  expectRejected({ ...positive, status: 1 }, 'failed process status accepted');
  expectRejected({ ...positive, status: null }, 'statusless process accepted');
  expectRejected({ ...positive, status: null, signal: 'SIGTERM' }, 'signaled process accepted');
  expectRejected({ ...positive, error: new Error('spawn failed') }, 'spawn error accepted');

  for (const [fixture, description] of [
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.01s' }] }), 'missing child terminal'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'FAIL', indent: 4, duration: '0.01s' }, { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'failed child'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'SKIP', indent: 4, duration: '0.01s' }, { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'skipped child'],
    [nestedChildFixture({ childRuns: ['sub-a', 'sub-a'], childTerminals: [{ name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.01s' }, { name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'duplicate child RUN'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.01s' }, { name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'duplicate child terminal'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.01s' }, { name: 'sub-a', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'reordered child terminal'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'PASS', indent: 4, duration: '0..01s' }, { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'malformed child duration'],
    [nestedChildFixture({ childTerminals: [{ name: 'foreign', kind: 'PASS', indent: 4, duration: '0.01s' }, { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'foreign child'],
    [nestedChildFixture({ childTerminals: [{ name: 'sub-a', kind: 'PASS', indent: 2, duration: '0.01s' }, { name: 'sub-b', kind: 'PASS', indent: 4, duration: '0.02s' }] }), 'malformed child indentation'],
  ]) expectRejected(fixture, `${description} inventory accepted`);

  const broken = {
    status: 1,
    signal: null,
    error: null,
    output: `=== RUN   ${mutantTest}\n--- FAIL: ${mutantTest} (0.00s)\n    server_test.go:1: ${mutantMarker}: unauthorized request reached backend`,
  };
  invariant(parseMutantFailure(broken), 'specific authorization mutant failure fixture was rejected');
  for (const invalid of [
    { ...broken, status: null },
    { ...broken, signal: 'SIGTERM' },
    { ...broken, error: new Error('spawn failed') },
    { ...broken, output: broken.output.replace(mutantTest, 'TestOther') },
    { ...broken, output: broken.output.replace(mutantMarker, 'unrelated failure') },
    { ...broken, output: broken.output.replace('--- FAIL:', '--- PASS:') },
  ]) invariant(!parseMutantFailure(invalid), 'mutant oracle accepted an unrelated failure');
}

function parseMutantFailure(result) {
  if (result.status !== 1 || result.signal != null || result.error != null) return false;
  const lines = result.output.split(/\r?\n/);
  const observations = lines.filter((line) => line.startsWith('=== RUN') || /^--- (PASS|FAIL|SKIP):/.test(line));
  if (observations.length !== 2) return false;
  const run = observations[0].match(/^=== RUN\s+(Test[A-Za-z0-9_]+)$/);
  const fail = observations[1].match(/^--- FAIL:\s+(Test[A-Za-z0-9_]+) \((?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)s\)$/);
  return run?.[1] === mutantTest && fail?.[1] === mutantTest && lines.some((line) => line.includes(mutantMarker));
}

function verifySourceOnly() {
  const server = readFileSync('internal/comfyharness/server.go', 'utf8');
  const tests = readFileSync('internal/comfyharness/server_test.go', 'utf8');
  const verifier = readFileSync('scripts/verify-comfy-discovery-harness.mjs', 'utf8');
  for (const route of ['GET /object_info', 'GET /system_stats']) invariant(server.includes(route), `missing exact route ${route}`);
  for (const control of [
    'comfyDiscoveryTimeout = 5 * time.Second',
    'maxObjectInfoBytes int64 = 64 << 20',
    'maxSystemStatsBytes int64 = 1 << 20',
    'http.ErrUseLastResponse',
    'io.LimitReader(response.Body, limit+1)',
    'utf8.Valid(body)',
    'r.URL.ForceQuery',
    'backend.RawQuery != "" || backend.ForceQuery || backend.Fragment != "" || backend.User != nil',
    'backend.Path, backend.RawPath = decodedPath, escapedPath',
    'backendURL, err := s.discoveryURL(r.URL.Path)',
    'validDiscoveryObject(body)',
  ]) invariant(server.includes(control), `missing source control: ${control}`);
  for (const name of requiredTests) invariant(tests.includes(`func ${name}(`), `missing required test ${name}`);
  invariant(tests.includes('started.Add(5*time.Second+100*time.Millisecond)'), 'deadline test does not assert the independent five-second bound');
  invariant(tests.includes(mutantMarker), 'authorization mutant test marker is missing');
  invariant(verifier.includes('spawnSync(') && verifier.includes("'-count=1'"), 'protocol mode must invoke uncached tests');
  invariant(verifier.includes('mkdtempSync(') && verifier.includes('unlinkSync(') && verifier.includes('rmdirSync(') && verifier.includes('readdirSync('), 'protocol mode must isolate and clean up only its known overlay files');
  verifyInventoryOracle();
  process.stdout.write('managed Comfy discovery source controls passed\n');
}

function runGo(args) {
  const result = spawnSync('go', args, {
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  return {
    status: result.status,
    signal: result.signal,
    error: result.error ?? null,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}`,
  };
}

function runAuthorizationMutant() {
  const sourcePath = resolve('internal/comfyharness/server.go');
  invariant(statSync(sourcePath).size <= 1024 * 1024, 'discovery source exceeds overlay read bound');
  const source = readFileSync(sourcePath, 'utf8');
  const guard = 'if r.Header.Get("Authorization") != s.options.Authorization {';
  const mutantGuard = 'if r.URL.Path != "/object_info" && r.Header.Get("Authorization") != s.options.Authorization {';
  invariant(source.split(guard).length === 2, 'authorization overlay guard is absent or ambiguous');

  const tempRoot = resolve(tmpdir());
  const overlayDirectory = mkdtempSync(join(tempRoot, 'comfy-discovery-auth-mutant-'));
  const createdFiles = [];
  try {
    const resolvedOverlay = resolve(overlayDirectory);
    invariant(resolvedOverlay.startsWith(`${tempRoot}${sep}`), 'mutation overlay escaped the platform temp directory');
    const mutantPath = join(resolvedOverlay, 'server-mutant.go');
    const overlayPath = join(resolvedOverlay, 'overlay.json');
    const mutantSource = source.replace(guard, mutantGuard);
    const overlay = JSON.stringify({ Replace: { [sourcePath]: mutantPath } });
    invariant(Buffer.byteLength(mutantSource, 'utf8') <= 1024 * 1024 && Buffer.byteLength(overlay, 'utf8') <= 4096, 'mutation overlay exceeds write bounds');
    writeFileSync(mutantPath, mutantSource, { flag: 'wx' });
    createdFiles.push(mutantPath);
    writeFileSync(overlayPath, overlay, { flag: 'wx' });
    createdFiles.push(overlayPath);

    const mutant = runGo([
      'test', '-count=1', '-v', `-overlay=${overlayPath}`,
      '-run', `^${mutantTest}$`, './internal/comfyharness',
    ]);
    invariant(parseMutantFailure(mutant), `authorization mutant did not fail at its exact behavioral assertion:\n${mutant.output}`);
  } finally {
    const entries = readdirSync(overlayDirectory);
    const knownNames = new Set(createdFiles.map((path) => path.slice(overlayDirectory.length + 1)));
    invariant(entries.every((entry) => knownNames.has(entry)), 'mutation overlay contains unexpected files; refusing cleanup');
    for (const path of createdFiles) unlinkSync(path);
    invariant(readdirSync(overlayDirectory).length === 0, 'mutation overlay directory is not empty after known-file cleanup');
    rmdirSync(overlayDirectory);
  }
}

function verifyProtocol() {
  verifyInventoryOracle();
  const pattern = `^(${requiredTests.join('|')})$`;
  const positive = runGo(['test', '-count=1', '-v', '-run', pattern, './internal/comfyharness']);
  invariant(positive.status === 0 && positive.signal == null && positive.error == null, `uncached harness regressions/discovery tests failed:\n${positive.output}`);
  parseInventory(positive);
  runAuthorizationMutant();
  process.stdout.write('managed Comfy discovery protocol verification passed\n');
}

const mode = process.argv[2];
try {
  if (mode === '--mode=source-only') verifySourceOnly();
  else if (mode === '--mode=protocol') verifyProtocol();
  else throw new Error('usage: node scripts/verify-comfy-discovery-harness.mjs --mode=source-only|--mode=protocol');
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
}
