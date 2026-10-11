#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && !['--faults', '--freshness', '--source-only'].includes(args[0]))) {
  throw new Error('usage: node scripts/verify-checkpoint-managed-binding.mjs [--faults|--freshness|--source-only]');
}
const mode = args[0] ?? 'default';
if (!['linux', 'win32'].includes(process.platform)) throw new Error(`unsupported verification host: ${process.platform}`);

const portable = [
  'TestCheckpointManagedBindingControls',
  'TestCheckpointManagedBindingFaultControls',
  'TestCheckpointManagedBindingFreshnessControls',
  'TestCheckpointManagedBindingUnsupportedPlatform',
];
const linux = [
  'TestCheckpointManagedBindingNestedObserverRouteAndNoFallback',
  'TestCheckpointManagedBindingObserverRoleRouting',
  'TestCheckpointManagedBindingOrchestrationPositive',
  'TestCheckpointManagedBindingOrchestrationFaultControls',
  'TestCheckpointManagedBindingObservationFreshness',
  'TestCheckpointManagedBindingAssociationTupleControls',
];
const top = [...portable, ...linux];
const children = [
  ...[
    'one_exact_alias', 'duplicate_alias_field', 'case_alias', 'ambiguous_model_list', 'wrong_model_object',
    'no_loaded_model', 'truncated_response', 'unexpected_metadata', 'trailing_data', 'alias_id_disagrees',
    'ambiguous_aliases', 'duplicate_alias_value', 'null_aliases', 'null_alias_member', 'null_tags', 'created_string',
    'null_tag_member', 'empty_tag_member', 'null_string_id', 'metadata_fraction', 'metadata_null', 'ftype_null', 'metadata_case_alias', 'wrong_owner', 'ftype_numeric_instead_of_string',
    'oversized_response',
  ].map((name) => `TestCheckpointManagedBindingControls/${name}`),
  ...[
    'positive_exact_argv', 'missing_argv0', 'context_substitution', 'slot_substitution', 'model_operand_confusion',
    'descriptor_confusion', 'staged_executable_argv0', 'extra_argv', 'snapshot_root_substitution',
    'placement_flag_substitution', 'empty_argument',
  ].map((name) => `TestCheckpointManagedBindingFaultControls/${name}`),
  ...[
    'staged_artifact_mismatch', 'argv0_staged_path_confusion', 'context_changed', 'ambiguous_current_alias',
    'wrong_initial_current_alias', 'physical_footprint_outside_plan', 'missing_physical_attribution',
    'plan_substitution_at_final_recheck', 'process_incarnation_changed', 'start_ticks_changed',
    'listener_socket_changed', 'unit_invocation_changed', 'unit_cgroup_changed',
  ].map((name) => `TestCheckpointManagedBindingOrchestrationFaultControls/${name}`),
  ...[
    'identity_evidence', 'endpoint', 'service_unit', 'boot_id', 'pid', 'start_ticks', 'listener_ip',
    'listener_port', 'listener_socket', 'executable_path', 'executable_hash', 'executable_device',
    'executable_inode', 'executable_size', 'model_path', 'model_hash', 'model_device', 'model_inode',
    'model_size', 'invocation', 'cgroup', 'receipt_evidence', 'receipt_model_argument', 'receipt_argv_hash',
    'receipt_binding_hash', 'receipt_nonce', 'receipt_endpoint', 'receipt_unit', 'receipt_unit_association',
    'receipt_boot_id', 'receipt_pid', 'receipt_start_ticks', 'receipt_socket', 'receipt_executable_path',
    'receipt_executable_hash', 'receipt_alias', 'artifact_path', 'artifact_device', 'artifact_inode',
    'artifact_size', 'artifact_hash', 'artifact_verity', 'receipt_executable_device', 'receipt_executable_inode',
    'receipt_executable_size', 'receipt_executable_verity', 'timestamps_and_measured_footprint_excluded',
  ].map((name) => `TestCheckpointManagedBindingAssociationTupleControls/${name}`),
];
const expected = [...top, ...children];
const portableExpected = [
  ...portable,
  ...children.filter((name) => name.startsWith('TestCheckpointManagedBindingControls/') || name.startsWith('TestCheckpointManagedBindingFaultControls/')),
];
const linuxExpected = [
  ...linux,
  ...children.filter((name) => name.startsWith('TestCheckpointManagedBindingOrchestrationFaultControls/') || name.startsWith('TestCheckpointManagedBindingAssociationTupleControls/')),
];
const sourcePaths = [
  'internal/nodeagent/checkpoint_managed_binding_test.go',
  'internal/nodeagent/checkpoint_managed_binding_linux_test.go',
];
const declaredSource = sourcePaths.map((file) => readFileSync(path.join(root, file), 'utf8')).join('\n');
const declared = [...declaredSource.matchAll(/^func (TestCheckpointManagedBinding\w+)\(/gm)].map((match) => match[1]);
if (declared.length !== top.length || new Set(declared).size !== declared.length || top.some((name) => !declared.includes(name)) || declared.some((name) => !top.includes(name))) {
  throw new Error('declared Go test inventory is missing, duplicated, or contains an unreviewed test');
}

const common = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_managed_binding.go'), 'utf8');
const linuxSource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_managed_binding_linux.go'), 'utf8');
const bridgeLinux = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_host_gpu_bridge_linux.go'), 'utf8');
const localObserverSource = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_local_observer_linux.go'), 'utf8');
const other = readFileSync(path.join(root, 'internal/nodeagent/checkpoint_managed_binding_other.go'), 'utf8');
const digest = common.slice(common.indexOf('func managedCheckpointCurrentIncarnation'), common.indexOf('func managedCheckpointExpectedArgv'));
const localObserverCallChainIsRetained = (managedSource, collectorSource) => /nestedFootprint:\s*observeNestedManagedCheckpointFootprintLocalObserver/.test(collectorSource) &&
  managedSource.includes('return observeNestedManagedCheckpointFootprintUsing(ctx, pid, expectedStartTicks, plan, placement, observeCheckpointHostGPUAttributionLocalObserver)');
if (!localObserverCallChainIsRetained(linuxSource, localObserverSource)) throw new Error('source contract assertion failed: actual local observer Using call chain is not retained');
const bypassedObserverCallChain = linuxSource.replace(
  'return observeNestedManagedCheckpointFootprintUsing(ctx, pid, expectedStartTicks, plan, placement, observeCheckpointHostGPUAttributionLocalObserver)',
  'return observeNestedManagedCheckpointFootprint(ctx, pid, expectedStartTicks, plan, placement)',
);
if (bypassedObserverCallChain === linuxSource || localObserverCallChainIsRetained(bypassedObserverCallChain, localObserverSource)) {
  throw new Error('source contract assertion failed: actual local observer Using call-chain bypass mutant was accepted');
}
for (const [name, okay] of [
  ['context-only public observer', /func ObserveCheckpointManagedLocalBinding\(ctx context\.Context\) \(CheckpointManagedBinding, error\)/.test(common)],
  ['fixed plan rechecks around current samples', linuxSource.split('recheckPlan(bounded, planPin)').length === 3],
  ['read-only custody opening and authenticated v2 receipt', linuxSource.includes('openCheckpointCustodyStoreReadOnly') && linuxSource.includes('store.VerifyBinding(callCtx, endpoint, checkpointIdentityServiceUnit)')],
  ['bounded pinned llama.cpp schema including meta and aliases', common.includes('checkpointManagedHTTPMax') && common.includes('"vocab_type"') && common.includes('"owned_by"') && common.includes('parseManagedCheckpointStringList')],
  ['exact original executable argv0 and descriptor model operand', common.includes('append([]string{plan.Executable.Path}, args...)') && common.includes('"/proc/self/fd/4"')],
  ['current alias equals plan at both observations', linuxSource.includes('if aliasFirst != plan.Alias') && linuxSource.includes('aliasSecond != plan.Alias')],
  ['one-card per-PID footprint attribution', linuxSource.includes('runCheckpointGPUProcessInventory(ctx)') && linuxSource.includes('readCheckpointProcessRSS(ctx, pid)')],
  ['actual local observer call chain with retained root collector and no nonroot fallback', linuxSource.includes('routeCheckpointManagedBindingObserver(ctx, os.Geteuid()') && linuxSource.includes('ObserveCheckpointLocalAssociation(callCtx)') && /if euid != 0 \{[\s\S]*localObserver\(ctx\)[\s\S]*return CheckpointManagedBinding\{\}, err[\s\S]*\}[\s\S]*return rootCollector\(ctx\)/.test(linuxSource) && localObserverCallChainIsRetained(linuxSource, localObserverSource) && linuxSource.includes('observeCheckpointHostGPUAttributionLocalObserver)') && /if nested \{[\s\S]*source\.nestedFootprint[\s\S]*else \{[\s\S]*source\.footprint/.test(linuxSource)],
  ['fixed node trust, held namespace identity, nonce, and signed response join', bridgeLinux.includes('checkpointNodeTrustPath') && bridgeLinux.includes('checkpointNodePublicKeyPath') && bridgeLinux.includes('rand.Read(nonce)') && bridgeLinux.includes('verifyCheckpointHostGPUResponseForRole(responseBytes, publicKey, request, expectedRole') && /func verifyCheckpointHostGPUResponseForRole\([\s\S]*?checkpointgpuobserver\.VerifyResponse\(raw, publicKey, request, nowUnixNS\)[\s\S]*?validateCheckpointHostGPUResponseRole\(response\.Role, expectedRole\)/.test(bridgeLinux) && bridgeLinux.includes('recheckCheckpointHeldLocalProcess(worker)') && bridgeLinux.includes('response.Peer.Namespace != self.namespace')],
  ['timestamps and measurements excluded from stable identity', digest.length > 0 && !/custody\.BindingSHA256/.test(digest) && !digest.includes('ObservedAt') && !digest.includes('GPUBytes') && !digest.includes('HostRSSBytes')],
  ['unsupported systems fail closed', other.includes('requires Linux process, systemd, CUDA, and custody observations')],
]) if (!okay) throw new Error(`source contract assertion failed: ${name}`);

if (mode === '--source-only') {
  console.log('checkpoint managed binding source-only verification passed');
  process.exit(0);
}

const env = { ...process.env, GOCACHE: path.join(root, '.unlazy/fleet-residency-v2/tmp/gocache-managed-binding') };
const deadline = Date.now() + 1_170_000;
function remaining() {
  const value = deadline - Date.now();
  if (value <= 0) throw new Error('managed-binding verifier reached its shared 1170-second deadline');
  return value;
}
function run(program, commandArgs, options = {}) {
  const result = spawnSync(program, commandArgs, { cwd: root, env, encoding: 'utf8', timeout: remaining(), maxBuffer: 1024 * 1024, windowsHide: true, ...options });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status !== 0) throw new Error(`${program} exited ${result.status ?? 'without status'}\n${output.slice(-8000)}`);
  return output;
}
function assertTranscriptInventory(transcript, label, names) {
  const events = new Map();
  for (const rawLine of transcript.split(/\r?\n/)) {
    const line = rawLine.trimStart();
    let match;
    let action;
    let name;
    if (line.startsWith('=== RUN')) {
      match = /^=== RUN\s+(\S+)\s*$/.exec(line);
      if (!match) throw new Error(`${label} contained a malformed RUN record: ${rawLine}`);
      action = 'RUN'; name = match[1];
    } else if (/^--- (PASS|SKIP|FAIL)(?:\s|:)/.test(line)) {
      match = /^--- (PASS|SKIP|FAIL):\s+(\S+?)(?:\s+\([^)]*\))?\s*$/.exec(line);
      if (!match) throw new Error(`${label} contained a malformed result record: ${rawLine}`);
      action = match[1]; name = match[2];
    } else {
      continue;
    }
    if (!names.includes(name)) throw new Error(`${label} emitted unreviewed, unexpected-nested, or unrelated test event ${action} ${name}`);
    const sequence = events.get(name) ?? [];
    sequence.push(action);
    events.set(name, sequence);
    if (sequence.length > 2) throw new Error(`${label} emitted duplicate test event ${action} ${name}`);
    if (action === 'SKIP' || action === 'FAIL') throw new Error(`${label} emitted ${action} for ${name}`);
  }
  if (events.size !== names.length) throw new Error(`${label} inventory incomplete; expected ${names.length} exact test names, observed ${events.size}`);
  for (const name of names) {
    const sequence = events.get(name);
    if (sequence.length !== 2 || sequence[0] !== 'RUN' || sequence[1] !== 'PASS') throw new Error(`${label} expected exactly RUN,PASS for ${name}, got ${sequence?.join(',') ?? 'none'}`);
  }
  return `RUN=${names.length} PASS=${names.length} SKIP=0 FAIL=0`;
}
function transcriptFromGoJSON(output) {
  const lines = [];
  for (const line of output.split(/\r?\n/)) {
    if (!line) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error('native go test emitted malformed JSON'); }
    if (!event.Test || !['run', 'pass', 'skip', 'fail'].includes(event.Action)) continue;
    if (event.Action === 'run') lines.push(`=== RUN   ${event.Test}`);
    else lines.push(`--- ${event.Action.toUpperCase()}: ${event.Test} (0.00s)`);
  }
  return lines.join('\n');
}
function transcriptParserControls(positiveTranscript, names, label) {
  assertTranscriptInventory(positiveTranscript, `${label} positive transcript`, names);
  const lines = positiveTranscript.split(/\r?\n/);
  const target = names.find((name) => name.includes('/')) ?? names[0];
  const runLine = `=== RUN   ${target}`;
  const passLine = lines.find((line) => line.trimStart().startsWith(`--- PASS: ${target} `)) ?? `--- PASS: ${target} (0.00s)`;
  const reject = (caseName, candidate) => {
    let rejected = false;
    try { assertTranscriptInventory(candidate, `${label} parser control ${caseName}`, names); } catch { rejected = true; }
    if (!rejected) throw new Error(`${label} transcript parser accepted negative control ${caseName}`);
  };
  reject('missing RUN', lines.filter((line) => line.trimStart() !== runLine).join('\n'));
  reject('missing PASS', lines.filter((line) => line.trimStart() !== passLine.trimStart()).join('\n'));
  reject('duplicate RUN', [...lines, runLine].join('\n'));
  reject('duplicate PASS', [...lines, passLine].join('\n'));
  reject('SKIP', lines.map((line) => line.trimStart() === passLine.trimStart() ? line.replace('--- PASS:', '--- SKIP:') : line).join('\n'));
  reject('FAIL', lines.map((line) => line.trimStart() === passLine.trimStart() ? line.replace('--- PASS:', '--- FAIL:') : line).join('\n'));
  reject('unexpected nested case', [...lines, `=== RUN   ${target}/unreviewed_child`, `--- PASS: ${target}/unreviewed_child (0.00s)`].join('\n'));
  reject('unrelated test', [...lines, '=== RUN   TestUnrelated', '--- PASS: TestUnrelated (0.00s)'].join('\n'));
  reject('malformed test event', [...lines, '=== RUN'].join('\n'));
}
function windowsPathToWsl(value) {
  const parsed = path.win32.parse(value);
  const drive = parsed.root.match(/^([A-Za-z]):\\$/)?.[1];
  if (!drive) throw new Error(`cannot map path into fixed Ubuntu WSL: ${value}`);
  return `/mnt/${drive.toLowerCase()}/${value.slice(parsed.root.length).split(/[\\/]+/).filter(Boolean).join('/')}`;
}
function runLinuxBinary(bin, names) {
  const linuxBin = process.platform === 'win32' ? windowsPathToWsl(bin) : bin;
  if (process.platform === 'win32') run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'chmod', '+x', linuxBin]);
  return process.platform === 'win32'
    ? run('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxBin, `-test.run=^(${names.join('|')})$`, '-test.count=1', '-test.timeout=60s', '-test.v'])
    : run(linuxBin, [`-test.run=^(${names.join('|')})$`, '-test.count=1', '-test.timeout=60s', '-test.v']);
}
function expectedFailure(program, commandArgs, testName, marker) {
  const result = spawnSync(program, commandArgs, { cwd: root, env, encoding: 'utf8', timeout: remaining(), maxBuffer: 1024 * 1024, windowsHide: true });
  if (result.error) throw result.error;
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.status !== 1 || result.signal || !output.includes(`--- FAIL: ${testName}`) || !output.includes(marker) || /panic:|fatal error:|test timed out/i.test(output)) {
    throw new Error(`implementation mutant did not reach expected assertion ${testName}: ${marker}\n${output.slice(-8000)}`);
  }
}

const temp = mkdtempSync(path.join(tmpdir(), 'checkpoint-managed-binding-'));
try {
  const nativeTop = process.platform === 'win32' ? portable : top;
  const nativeNames = process.platform === 'win32' ? portableExpected : expected;
  const native = run('go', ['test', '-json', './internal/nodeagent', '-run', `^(${nativeTop.join('|')})$`, '-count=1', '-timeout=60s']);
  const nativeTranscript = transcriptFromGoJSON(native);
  const nativeCount = assertTranscriptInventory(nativeTranscript, 'native suite', nativeNames);
  transcriptParserControls(nativeTranscript, nativeNames, 'native suite');
  let linuxCount = '';
  if (process.platform === 'win32') {
    const binary = path.join(temp, 'nodeagent-linux.test');
    run('go', ['test', '-c', '-o', binary, './internal/nodeagent'], { env: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' } });
    const output = runLinuxBinary(binary, linux);
    assertTranscriptInventory(output, 'WSL Linux suite', linuxExpected);
    transcriptParserControls(output, linuxExpected, 'WSL Linux suite');
    linuxCount = ` LINUX_RUN=${linuxExpected.length} LINUX_PASS=${linuxExpected.length}`;
  }
  if (mode === '--faults') await implementationMutants(temp);
  const marker = mode === '--faults' ? 'checkpoint managed binding fault verification passed'
    : mode === '--freshness' ? 'checkpoint managed binding freshness verification passed'
      : 'checkpoint managed binding verification passed';
  console.log(`${nativeCount}${linuxCount}`);
  console.log(`TESTS=${nativeNames.join(',')}${process.platform === 'win32' ? `; Linux=${linuxExpected.join(',')}` : ''}`);
  console.log(marker);
} finally {
  rmSync(temp, { recursive: true, force: true });
}

async function implementationMutants(tempDir) {
  const mutants = [
    {
      name: 'argv-guard', file: 'internal/nodeagent/checkpoint_managed_binding_linux.go',
      needle: 'if err != nil || !equalCheckpointArgv(argv, expectedArgv) {', replacement: 'if err != nil || len(expectedArgv) < 0 {',
      extra: [{ needle: 'if err != nil || !equalCheckpointArgv(argvAfter, expectedArgv) || !equalCheckpointArgv(argvAfter, argv) {', replacement: 'if err != nil || len(expectedArgv) < 0 || len(argvAfter) < 0 {' }],
      test: 'TestCheckpointManagedBindingOrchestrationFaultControls/argv0_staged_path_confusion', marker: 'managed association fault was accepted',
    },
    {
      name: 'final-plan-recheck', file: 'internal/nodeagent/checkpoint_managed_binding_linux.go',
      needle: 'if err := recheckPlan(bounded, planPin); err != nil {\n\t\treturn CheckpointManagedBinding{}, fmt.Errorf("fixed managed plan changed during observation: %w", err)',
      replacement: 'if err := func() error { return nil }(); err != nil {\n\t\treturn CheckpointManagedBinding{}, fmt.Errorf("fixed managed plan changed during observation: %w", err)',
      test: 'TestCheckpointManagedBindingOrchestrationFaultControls/plan_substitution_at_final_recheck', marker: 'managed association fault was accepted',
    },
    {
      name: 'association-guard', file: 'internal/nodeagent/checkpoint_managed_binding_linux.go',
      needle: 'if err := validateManagedCheckpointAssociation(second, plan); err != nil || !sameManagedCheckpointAssociation(first, second) {', replacement: 'if false {',
      test: 'TestCheckpointManagedBindingOrchestrationFaultControls/process_incarnation_changed', marker: 'managed association fault was accepted',
    },
    {
      name: 'pinned-runtime-parser', file: 'internal/nodeagent/checkpoint_managed_binding.go',
      needle: 'owner != "llamacpp"', replacement: 'owner != "not-llamacpp"',
      test: 'TestCheckpointManagedBindingControls/one_exact_alias', marker: 'pinned llama.cpp schema was rejected',
    },
  ];
  for (const mutant of mutants) {
    const originalPath = path.join(root, mutant.file);
    const original = readFileSync(originalPath, 'utf8');
    if (original.split(mutant.needle).length !== 2 || (mutant.extra ?? []).some(({ needle }) => original.split(needle).length !== 2)) throw new Error(`${mutant.name} mutation anchor is not unique`);
    const mutatedPath = path.join(tempDir, `${mutant.name}.go`);
    const overlayPath = path.join(tempDir, `${mutant.name}.overlay.json`);
    let mutated = original.replace(mutant.needle, mutant.replacement);
    for (const { needle, replacement } of mutant.extra ?? []) mutated = mutated.replace(needle, replacement);
    writeFileSync(mutatedPath, mutated, 'utf8');
    writeFileSync(overlayPath, JSON.stringify({ Replace: { [originalPath]: mutatedPath } }), 'utf8');
    if (process.platform === 'linux') {
      expectedFailure('go', ['test', `-overlay=${overlayPath}`, './internal/nodeagent', '-run', `^${mutant.test}$`, '-count=1', '-timeout=60s', '-v'], mutant.test, mutant.marker);
    } else {
      const binary = path.join(tempDir, `${mutant.name}.test`);
      run('go', ['test', '-c', `-overlay=${overlayPath}`, '-o', binary, './internal/nodeagent'], { env: { ...env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0' } });
      const linuxBin = windowsPathToWsl(binary);
      run('wsl.exe', ['-d', 'Ubuntu', '--exec', 'chmod', '+x', linuxBin]);
      expectedFailure('wsl.exe', ['-d', 'Ubuntu', '--exec', linuxBin, `-test.run=^${mutant.test}$`, '-test.count=1', '-test.timeout=60s', '-test.v'], mutant.test, mutant.marker);
    }
  }
}
