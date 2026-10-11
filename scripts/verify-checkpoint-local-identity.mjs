import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const modes = process.argv.slice(2);
if (modes.length > 1 || (modes.length === 1 && !['--faults', '--artifacts'].includes(modes[0]))) {
  console.error('usage: node scripts/verify-checkpoint-local-identity.mjs [--faults|--artifacts]');
  process.exit(2);
}
const mode = modes[0] ?? '';

const allTests = [
  'TestCheckpointLocalIdentityRequestValidation',
  'TestCheckpointLocalIdentityFingerprintBindsProcessAndArtifact',
  'TestCheckpointLocalIdentityLinuxObserverAcceptsExactMappedArtifact',
  'TestCheckpointLocalIdentityLinuxObserverRejectsListenerOwnershipMismatch',
  'TestCheckpointLocalIdentityLinuxObserverRejectsAmbiguousListeners',
  'TestCheckpointLocalIdentityLinuxObserverRejectsUnmappedArtifact',
  'TestCheckpointLocalIdentityLinuxObserverRejectsIncompleteMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsUnreadableMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsWritableMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsSharedMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsChangedProcessIncarnation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsChangedMainPID',
  'TestCheckpointLocalIdentityLinuxObserverRejectsExecutableMismatch',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelDigestMismatch',
  'TestCheckpointLocalIdentityLinuxObserverRejectsSymlinkModelPath',
  'TestCheckpointLocalIdentityLinuxObserverRejectsRemoteEndpointAndUnit',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelSymlinkSwapDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsExecutableChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsLoadedMappingChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxProcReadersSeeRealListenerAndMapping',
  'TestCheckpointLocalIdentityClockStepsNeverVerifyLoadProvenance',
];

const faultTests = allTests.filter((name) => name.includes('Reject'));
const portableTests = [
  'TestCheckpointLocalIdentityRequestValidation',
  'TestCheckpointLocalIdentityFingerprintBindsProcessAndArtifact',
  'TestCheckpointLocalIdentityClockStepsNeverVerifyLoadProvenance',
];
const artifactTests = [
  'TestCheckpointLocalIdentityLinuxObserverAcceptsExactMappedArtifact',
  'TestCheckpointLocalIdentityLinuxObserverRejectsUnmappedArtifact',
  'TestCheckpointLocalIdentityLinuxObserverRejectsIncompleteMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsUnreadableMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsWritableMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsSharedMapping',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelDigestMismatch',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsModelSymlinkSwapDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsExecutableChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsLoadedMappingChangedDuringObservation',
  'TestCheckpointLocalIdentityLinuxObserverRejectsSymlinkModelPath',
  'TestCheckpointLocalIdentityLinuxProcReadersSeeRealListenerAndMapping',
];
const source = readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_identity_test.go'), 'utf8')
  + readFileSync(path.join(repoRoot, 'internal/nodeagent/checkpoint_identity_linux_test.go'), 'utf8');
const declared = new Set([...source.matchAll(/^func (TestCheckpointLocalIdentity\w+)\(/gm)].map((match) => match[1]));
const missing = allTests.filter((name) => !declared.has(name));
if (missing.length) throw new Error(`required observer tests are missing: ${missing.join(', ')}`);
if (declared.size !== allTests.length) {
  const unexpected = [...declared].filter((name) => !allTests.includes(name));
  if (unexpected.length) throw new Error(`unreviewed CheckpointLocalIdentity tests were added: ${unexpected.join(', ')}`);
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 600_000,
    maxBuffer: 4 * 1024 * 1024,
    ...options,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    process.stderr.write(result.stdout ?? '');
    process.stderr.write(result.stderr ?? '');
    throw new Error(`${program} exited ${result.status ?? 'without a status'}`);
  }
  return (result.stdout ?? '') + (result.stderr ?? '');
}

function assertPassed(output, expected, label) {
  const passed = new Set();
  const skipped = new Set();
  for (const line of output.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const event = JSON.parse(trimmed);
      if (!event.Test) continue;
      if (event.Action === 'pass') passed.add(event.Test);
      if (event.Action === 'skip') skipped.add(event.Test);
    } catch {
      const pass = trimmed.match(/^--- PASS: ([^\s(]+)/);
      const skip = trimmed.match(/^--- SKIP: ([^\s(]+)/);
      if (pass) passed.add(pass[1]);
      if (skip) skipped.add(skip[1]);
    }
  }
  const absent = expected.filter((name) => !passed.has(name));
  const unexpectedSkips = expected.filter((name) => skipped.has(name));
  if (absent.length || unexpectedSkips.length) {
    throw new Error(`${label} did not execute/pass exact required tests; absent=${absent.join(', ') || 'none'} skipped=${unexpectedSkips.join(', ') || 'none'}`);
  }
}

const mutants = [
  {
    name: 'listener-owner-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsListenerOwnershipMismatch',
    failureMarker: 'accepted a service process that did not own the listener socket',
    replacements: [
      ['if !owned {', 'if false && !owned {'],
      ['if err != nil || !ownedAfter {', 'if err != nil || (!ownedAfter && false) {'],
    ],
  },
  {
    name: 'observed-mapping-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsUnmappedArtifact',
    failureMarker: 'accepted a model found only on disk but not mapped in the listener process',
    replacements: [
      ['if len(segments) == 0 {', 'if false && len(segments) == 0 {'],
      ['if cursor < uint64(fileSize) {', 'if false && cursor < uint64(fileSize) {'],
    ],
  },
  {
    name: 'model-pin-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsModelDigestMismatch',
    failureMarker: 'accepted model bytes outside the allowlist',
    replacements: [['if !strings.EqualFold(digest, req.ExpectedModelSHA256) {', 'if false && !strings.EqualFold(digest, req.ExpectedModelSHA256) {']],
  },
  {
    name: 'readable-private-mapping-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsUnreadableMapping',
    failureMarker: 'accepted a PROT_NONE mapping as readable model bytes',
    replacements: [['if fields[1] != "r--p" {', 'if false && fields[1] != "r--p" {']],
  },
  {
    name: 'executable-final-stat-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsExecutableChangedDuringObservation',
    failureMarker: 'accepted an executable modified after hashing but before final identity validation',
    replacements: [['if exeAfterIdentity != exeBefore {', 'if false && exeAfterIdentity != exeBefore {']],
  },
  {
    name: 'observed-mapping-final-check',
    test: 'TestCheckpointLocalIdentityLinuxObserverRejectsLoadedMappingChangedDuringObservation',
    failureMarker: 'accepted a listener process after its sampled GGUF mapping disappeared',
    replacements: [['if err != nil || mappedBytesAfter != mappedBytes {', 'if false && (err != nil || mappedBytesAfter != mappedBytes) {']],
  },
];

const isLinux = process.platform === 'linux';
const isWindows = process.platform === 'win32';
if (!isLinux && !isWindows) throw new Error(`unsupported verification host: ${process.platform}`);

if (mode === '--artifacts') {
  if (isLinux) {
    for (const name of artifactTests) {
      const output = run('go', ['test', '-json', './internal/nodeagent', '-run', name, '-count=1']);
      assertPassed(output, [name], `Linux artifact test ${name}`);
    }
  } else {
    const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-local-artifacts-'));
    const binaryPath = path.join(tempDir, 'nodeagent-linux.test');
    try {
      run('go', ['test', '-c', '-o', binaryPath, './internal/nodeagent'], {
        env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
      });
      const windowsPath = binaryPath.replaceAll('\\', '/');
      const linuxPath = execFileSync('wsl.exe', ['-d', 'Ubuntu', '--', 'wslpath', '-a', windowsPath], {
        cwd: repoRoot, encoding: 'utf8', timeout: 30_000,
      }).trim();
      if (!linuxPath.startsWith('/')) throw new Error('WSL did not return an absolute Linux test-binary path');
      run('wsl.exe', ['-d', 'Ubuntu', '--', 'chmod', '+x', linuxPath]);
      for (const name of artifactTests) {
        const output = run('wsl.exe', ['-d', 'Ubuntu', '--', linuxPath, `-test.run=${name}`, '-test.count=1', '-test.v']);
        assertPassed(output, [name], `WSL artifact test ${name}`);
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  }
  console.log(`checkpoint local artifact verification passed; artifact-tests=${artifactTests.length}`);
  process.exit(0);
}

if (isLinux) {
  const output = run('go', ['test', '-json', './internal/nodeagent', '-run', 'CheckpointLocalIdentity', '-count=1']);
  assertPassed(output, allTests, 'Linux observer suite');
} else {
  const nativeOutput = run('go', ['test', '-json', './internal/nodeagent', '-run', 'TestCheckpointLocalIdentity', '-count=1']);
  assertPassed(nativeOutput, portableTests, 'portable observer suite');
  const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-local-identity-'));
  const binaryPath = path.join(tempDir, 'nodeagent-linux.test');
  try {
    run('go', ['test', '-c', '-o', binaryPath, './internal/nodeagent'], {
      env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
    });
    const windowsPath = binaryPath.replaceAll('\\', '/');
    const linuxPath = execFileSync('wsl.exe', ['-d', 'Ubuntu', '--', 'wslpath', '-a', windowsPath], {
      cwd: repoRoot, encoding: 'utf8', timeout: 30_000,
    }).trim();
    if (!linuxPath.startsWith('/')) throw new Error('WSL did not return an absolute Linux test-binary path');
    run('wsl.exe', ['-d', 'Ubuntu', '--', 'chmod', '+x', linuxPath]);
    const linuxOutput = run('wsl.exe', ['-d', 'Ubuntu', '--', linuxPath, '-test.run=CheckpointLocalIdentity', '-test.count=1', '-test.v']);
    assertPassed(linuxOutput, allTests, 'WSL Linux observer suite');
    if (mode === '--faults') {
      for (const name of faultTests) {
        const output = run('wsl.exe', ['-d', 'Ubuntu', '--', linuxPath, `-test.run=${name}`, '-test.count=1', '-test.v']);
        assertPassed(output, [name], `WSL fault test ${name}`);
      }
      runMutants({ platform: 'windows', linuxPath, tempDir });
    }
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
}

if (mode === '--faults') {
  if (isLinux) {
    for (const name of faultTests) {
      const output = run('go', ['test', '-json', './internal/nodeagent', '-run', name, '-count=1']);
      assertPassed(output, [name], `Linux fault test ${name}`);
    }
    const tempDir = mkdtempSync(path.join(tmpdir(), 'checkpoint-local-identity-mutants-'));
    try { runMutants({ platform: 'linux', tempDir }); } finally { rmSync(tempDir, { recursive: true, force: true }); }
  }
  console.log(`checkpoint local identity fault verification passed; fault-tests=${faultTests.length}; compiling-mutants=${mutants.length}`);
} else {
  console.log(`checkpoint local identity verification passed; observer-tests=${allTests.length}`);
}

function runMutants({ platform, linuxPath, tempDir }) {
  const sourcePath = path.join(repoRoot, 'internal/nodeagent/checkpoint_identity_linux.go');
  const original = readFileSync(sourcePath, 'utf8');
  for (const mutant of mutants) {
    let mutated = original;
    for (const [needle, replacement] of mutant.replacements) {
      const occurrences = mutated.split(needle).length - 1;
      if (occurrences !== 1) throw new Error(`${mutant.name} anchor count is ${occurrences}; expected exactly one`);
      mutated = mutated.replace(needle, replacement);
    }
    const mutantSource = path.join(tempDir, `${mutant.name}.go`);
    const overlayPath = path.join(tempDir, `${mutant.name}.overlay.json`);
    const binaryPath = path.join(tempDir, `${mutant.name}.test`);
    writeFileSync(mutantSource, mutated, 'utf8');
    writeFileSync(overlayPath, JSON.stringify({ Replace: { [sourcePath]: mutantSource } }), 'utf8');
    if (platform === 'linux') {
      let output;
      try { output = runExpectFailure('go', ['test', `-overlay=${overlayPath}`, './internal/nodeagent', '-run', mutant.test, '-count=1']); }
      catch (error) { throw new Error(`${mutant.name}: ${error.message}`); }
      if (!output.includes(`--- FAIL: ${mutant.test}`) || !output.includes(mutant.failureMarker)) throw new Error(`${mutant.name} did not fail through its intended assertion`);
      continue;
    }
    run('go', ['test', '-c', `-overlay=${overlayPath}`, '-o', binaryPath, './internal/nodeagent'], {
      env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' },
    });
    const windowsPath = binaryPath.replaceAll('\\', '/');
    const wslBinaryPath = execFileSync('wsl.exe', ['-d', 'Ubuntu', '--', 'wslpath', '-a', windowsPath], {
      cwd: repoRoot, encoding: 'utf8', timeout: 30_000,
    }).trim();
    if (!wslBinaryPath.startsWith('/')) throw new Error(`${mutant.name} WSL path conversion failed`);
    run('wsl.exe', ['-d', 'Ubuntu', '--', 'chmod', '+x', wslBinaryPath]);
    let output;
    try { output = runExpectFailure('wsl.exe', ['-d', 'Ubuntu', '--', wslBinaryPath, `-test.run=${mutant.test}`, '-test.count=1', '-test.v']); }
    catch (error) { throw new Error(`${mutant.name}: ${error.message}`); }
    if (!output.includes(`--- FAIL: ${mutant.test}`) || !output.includes(mutant.failureMarker)) throw new Error(`${mutant.name} did not fail through its intended assertion`);
  }
}

function runExpectFailure(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    timeout: 600_000,
    maxBuffer: 4 * 1024 * 1024,
    ...options,
  });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status === 0) throw new Error(`${program} unexpectedly passed a weakened-observer mutation`);
  return output;
}
