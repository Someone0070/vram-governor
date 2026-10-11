import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2];
const modes = new Set(['--mode=authority', '--mode=kernel', '--mode=kernel-opath-mutant', '--mode=regressions', '--mode=source-only']);
if (process.argv.length !== 3 || !modes.has(mode)) {
  console.error('usage: node scripts/verify-checkpoint-local-observer.mjs --mode=authority|kernel|kernel-opath-mutant|regressions|source-only');
  process.exit(2);
}

const owned = [
  'internal/nodeagent/checkpoint_local_observer.go',
  'internal/nodeagent/checkpoint_local_observer_linux.go',
  'internal/nodeagent/checkpoint_local_observer_other.go',
  'internal/nodeagent/checkpoint_local_observer_test.go',
  'internal/nodeagent/checkpoint_local_observer_linux_test.go',
  'internal/nodeagent/checkpoint_local_observer_kernel_linux_test.go',
  'cmd/checkpoint-local-observer/main_linux.go',
  'cmd/checkpoint-local-observer/main_other.go',
  'deploy/checkpoint-local-observer.service',
  'scripts/verify-checkpoint-local-observer.mjs',
];

function run(program, args, options = {}) {
  const result = spawnSync(program, args, {
    cwd: root, encoding: 'utf8', timeout: 210_000, maxBuffer: 16 * 1024 * 1024,
    ...options,
  });
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0) {
    process.stderr.write(output);
    throw new Error(`${program} exited ${result.status ?? 'without a status'}`);
  }
  return output;
}

function inventory(output, expected) {
  const runs = new Map(), passes = new Map(), failures = [], skips = [], malformed = [];
  for (const line of output.split(/\r?\n/)) {
    if (/^\s*=== RUN(?:\s|$)/.test(line)) {
      const match = line.match(/^\s*=== RUN\s+(\S+)\s*$/);
      if (!match) malformed.push(line); else runs.set(match[1], (runs.get(match[1]) ?? 0) + 1);
    }
    if (/^\s*--- (PASS|SKIP|FAIL):/.test(line)) {
      const match = line.match(/^\s*--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
      if (!match) malformed.push(line);
      else if (match[1] === 'PASS') passes.set(match[2], (passes.get(match[2]) ?? 0) + 1);
      else if (match[1] === 'SKIP') skips.push(match[2]);
      else failures.push(match[2]);
    }
  }
  const missingRuns = expected.filter((name) => runs.get(name) !== 1);
  const missingPasses = expected.filter((name) => passes.get(name) !== 1);
  const unexpectedRuns = [...runs.keys()].filter((name) => !expected.includes(name));
  const unexpectedPasses = [...passes.keys()].filter((name) => !expected.includes(name));
  if (missingRuns.length || missingPasses.length || unexpectedRuns.length || unexpectedPasses.length || failures.length || skips.length || malformed.length) {
    throw new Error(`exact RUN/PASS inventory mismatch: missing-run=${missingRuns}; missing-pass=${missingPasses}; unexpected-run=${unexpectedRuns}; unexpected-pass=${unexpectedPasses}; failures=${failures}; skips=${skips}; malformed=${malformed}`);
  }
}

function selfTestInventory() {
  inventory('=== RUN   TestA\n--- PASS: TestA (0.00s)\n', ['TestA']);
  const negatives = [
    ['missing RUN', '--- PASS: TestA (0.00s)\n'],
    ['duplicate RUN', '=== RUN TestA\n=== RUN TestA\n--- PASS: TestA (0.00s)\n'],
    ['missing PASS', '=== RUN TestA\n'],
    ['duplicate PASS', '=== RUN TestA\n--- PASS: TestA (0.00s)\n--- PASS: TestA (0.00s)\n'],
    ['skip', '=== RUN TestA\n--- SKIP: TestA (0.00s)\n'],
    ['failure', '=== RUN TestA\n--- FAIL: TestA (0.00s)\n'],
    ['unexpected event', '=== RUN TestA\n=== RUN TestB\n--- PASS: TestA (0.00s)\n--- PASS: TestB (0.00s)\n'],
    ['malformed event', '=== RUN\n--- PASS: TestA\n'],
  ];
  for (const [label, output] of negatives) {
    let rejected = false;
    try { inventory(output, ['TestA']); } catch { rejected = true; }
    assert(rejected, `inventory parser accepted ${label}`);
  }
}
selfTestInventory();

function assertParentReportPathRole(kernel) {
  const helperSignature = 'checkpointLocalObserverResolveHeldParentReportPath(dir *os.File, heldInfo os.FileInfo, readlink func(string) (string, error)) (string, error) {';
  const helper = extractGoFunction(kernel, helperSignature, 'held report path resolver');
  assert(helper.includes('filepath.Join("/proc/self/fd", strconv.Itoa(int(dir.Fd())))') &&
    !helper.includes('checkpointLocalObserverReportFD') && helper.includes('readlink(fdPath)') &&
    helper.includes('filepath.IsAbs(resolved)') && helper.includes('os.Lstat(resolved)') &&
    helper.includes('os.SameFile(before, named)') && helper.includes('held report path identity mismatch') &&
    helper.includes('Mode().Perm() != 0700') && helper.includes('os.ModeSymlink') &&
    helper.includes('heldStat.Uid != 0') && helper.includes('beforeStat.Uid != 0') &&
    helper.includes('namedStat.Uid != 0') && helper.includes('currentStat.Uid != 0') &&
    helper.includes('heldStat.Dev != beforeStat.Dev') && helper.includes('heldStat.Ino != beforeStat.Ino') &&
    helper.includes('namedStat.Dev != beforeStat.Dev') && helper.includes('namedStat.Ino != beforeStat.Ino') &&
    helper.includes('currentStat.Dev != beforeStat.Dev') && helper.includes('currentStat.Ino != beforeStat.Ino'),
  'held report path resolver must derive /proc path from the supplied report descriptor and retain path, mode, owner, no-symlink, dev/inode, and currentness guards');

  const armSignature = 'checkpointLocalObserverKernelArmParentDeathCoordinator(t *testing.T, root string, rootStat *syscall.Stat_t, worker, replacement, unrelated, broker *checkpointLocalObserverFixtureUnit) {';
  const arm = extractGoFunction(kernel, armSignature, 'unit-owning parent report arm');
  const roleAt = arm.indexOf('int(reportDir.Fd()) != checkpointLocalObserverParentReportFD');
  const positiveAt = arm.indexOf('positiveReportPath, positivePathErr := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, func(fdPath string) (string, error) {');
  const decoyAt = arm.indexOf('_, decoyPathErr := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, func(fdPath string) (string, error) {');
  const realLookupAt = arm.indexOf('reportDirPath, err := checkpointLocalObserverResolveHeldParentReportPath(reportDir, reportInfo, os.Readlink)');
  const coordinatorStartAt = arm.indexOf('coordinator := exec.Command(');
  assert(roleAt >= 0 && arm.includes('checkpointLocalObserverParentReportFD != 3') && arm.includes('checkpointLocalObserverReportFD != 10') &&
    positiveAt > roleAt && decoyAt > positiveAt && realLookupAt > decoyAt && coordinatorStartAt > realLookupAt,
  'unit-owning parent must execute fd3 positive, distinct-root decoy rejection, then real held-fd lookup before coordinator start');
  assert(arm.includes('fdPath != filepath.Join("/proc/self/fd", strconv.Itoa(checkpointLocalObserverParentReportFD))') &&
    arm.includes('return os.Readlink(fdPath)') && arm.includes('return root, nil') &&
    arm.includes('decoyPathErr.Error() != "held report path identity mismatch"') &&
    arm.includes('os.SameFile(reportInfo, rootInfo)'),
  'real-Go path controls must assert exact fd3 readlink, delegate positive resolution, and specifically reject the independently distinct existing fixture-root decoy');
  assert(!arm.includes('t.Run(') && !arm.includes('__CHECKPOINT_LOCAL_OBSERVER_'), 'report role controls must not add a RUN name or marker');
  const body = extractGoFunction(kernel, 'checkpointLocalObserverKernelFixtureBody(t *testing.T, abruptParent bool) {', 'existing kernel fixture body');
  assert(body.includes('checkpointLocalObserverKernelArmParentDeathCoordinator(t, root, rootStat, workerUnit, replacementUnit, unrelatedUnit, brokerUnit)'),
    'held report path controls are not reachable from the existing inventoried kernel fixture');
}

function selfTestParentReportPathRole(kernel) {
  assertParentReportPathRole(kernel);
  const before = 'fdPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(dir.Fd())))';
  const after = 'fdPath := filepath.Join("/proc/self/fd", strconv.Itoa(checkpointLocalObserverReportFD))';
  assert(kernel.split(before).length === 2, 'coordinator-fd role mutant anchor must be exact-once');
  const coordinatorRoleMutant = kernel.replace(before, after);
  assert.throws(() => assertParentReportPathRole(coordinatorRoleMutant), /held report path resolver must derive/,
    'reverting held path lookup to coordinator fd10 must fail the actual source predicate after its known-positive source case');
}

function sourceContracts() {
  const sources = new Map(owned.map((name) => [name, readFileSync(path.join(root, name), 'utf8')]));
  const common = sources.get(owned[0]);
  const linux = sources.get(owned[1]);
  const other = sources.get(owned[2]);
  const kernel = sources.get(owned[5]);
  const entry = sources.get(owned[6]);
  const unit = sources.get(owned[8]);
  const verifier = sources.get(owned[9]);
  assertSearchOnlyTrustRootSource(linux);
  assertLocalCollectorRoleRoute(linux);
  assertKernelSearchRootFixtureContract(kernel);
  assertOuterFailureDiagnosticSource(kernel);
  selfTestParentReportPathRole(kernel);
  assertRegisteredSearchRootMutant(verifier);
  const required = [
    [common, 'checkpointLocalObserverSigningDomain', 'domain-separated signatures'],
    [common, 'ed25519.Verify(public, signed, signature)', 'signature verification'],
    [common, 'checkpointLocalObserverRejectDuplicateKeys', 'duplicate-key rejection'],
    [common, 'DisallowUnknownFields()', 'unknown-field rejection'],
    [common, 'checkpointLocalObserverMaxFrame', 'bounded wire frames'],
    [linux, 'checkpointLocalObserverProductionConfig()', 'fixed production paths'],
    [linux, 'checkpointLocalObserverDecodePolicy(policyBytes)', 'single strict typed canonical policy parser'],
    [linux, 'checkpointLocalObserverPeerMatches(peerUID, peerGID, policy)', 'actual SO_PEERCRED UID/GID allowlist'],
    [linux, 'return uid == policy.PeerUID && gid == policy.PeerGID', 'exact SO_PEERCRED policy comparison'],
    [linux, 'return cred.Uid, cred.Gid, int(cred.Pid), nil', 'kernel-reported peer group admission'],
    [linux, 'peer.exeSHA256, policy.ExecutableSHA256', 'peer executable digest allowlist'],
    [linux, 'peer.cgroup != policy.ControlGroup', 'peer cgroup allowlist'],
    [linux, 'checkpointLocalObserverCheckFilePin(pubPin)', 'held public-key currentness'],
    [linux, 'checkpointLocalPIDFDAlive(worker.pidfd)', 'held cross-UID worker pidfd currentness'],
    [linux, 'observeNestedManagedCheckpointFootprintLocalObserver', 'role-bound local-observer nested host-GPU route'],
    [linux, 'checkpointWorkerUsesNestedPIDNamespace', 'nested worker namespace route'],
    [linux, 'checkpointLocalObserverBindingStable(first, second)', 'full stable binding authority join'],
    [linux, 'checkpointLocalObserverIdentityMatches(workerIdentity, worker2Identity)', 'used process currentness equality'],
    [other, 'supported only on Linux', 'unsupported-platform fail-closed path'],
    [entry, 'RunCheckpointLocalObserver(ctx)', 'fixed-only command entrypoint'],
    [entry, 'err != context.Canceled', 'cleanup failures remain visible during cancellation'],
    [kernel, 'checkpointLocalObserverKernelOptIn', 'explicit kernel fixture admission'],
    [kernel, 'systemd-run', 'isolated transient-unit fixture'],
    [kernel, '--property=CapabilityBoundingSet=CAP_SYS_PTRACE', 'transient broker exact capability bound'],
    [kernel, '--property=AmbientCapabilities=CAP_SYS_PTRACE', 'transient broker exact ambient capability'],
    [kernel, '--property=SystemCallFilter=~ptrace process_vm_writev', 'transient broker process-control syscall denylist'],
    [kernel, '--property=RuntimeMaxSec=200s', 'independent fixture unit maximum lifetime'],
    [kernel, 'checkpointLocalObserverAssertEffectiveBrokerUnit(brokerUnit, groupID)', 'effective broker security properties are checked against the held unit'],
    [kernel, 'fields["Seccomp"] != "2"', 'active seccomp filter is required'],
    [kernel, 'strconv.ParseUint(fields[key], 16, 64)', 'capability masks are parsed as hexadecimal values'],
    [kernel, 'deniedSet["ptrace"]', 'effective systemd syscall denylist is parsed as a set'],
    [kernel, 'currentStart != fixture.start', 'broker process identity is rechecked after property observation'],
    [kernel, 'err != context.Canceled', 'joined server cleanup errors remain visible during cancellation'],
    [kernel, '--property=Group=" + group', 'transient broker production group'],
    [kernel, 'InvocationID', 'pinned fixture unit invocation identity'],
    [kernel, 'unix.PidfdSendSignal(fixture.pidfd, unix.SIGTERM, nil, 0)', 'exact held-pidfd-only fixture termination'],
    [kernel, 'CAP_SYS_PTRACE_ONLY_ROOT_VRAM_GROUP_NNP', 'tagged broker capability and group posture positive'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_GID_DENIED__', 'actual wrong peer GID denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_KEY_DENIED__', 'wrong-key response denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_NONCE_DENIED__', 'wrong-nonce response denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_REPLACED_DENIED__', 'replacement-worker denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_EXIT_DENIED__', 'independent worker-exit denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_IDENTITY_SUBSTITUTION_DENIED__', 'signed caller identity substitution denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_NAMESPACE_SUBSTITUTION_DENIED__', 'worker namespace substitution denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_KEY_SUBSTITUTION_DENIED__', 'public-key path substitution denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__', 'unprivileged public-key read through search-only trust root'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_ROOT_SEARCH_DENIED__', 'missing trust-root search denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_GROUP_DENIED__', 'wrong public-key group denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_MODE_DENIED__', 'wrong public-key mode denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_SUBSTITUTION_DENIED__', 'symlink-substituted trust-root parent denial'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_PERMISSION_DENIED__', 'missing-search, wrong-group, and wrong-mode denials'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_READ_POSITIVE__', 'exact public-key leaf metadata positive'],
    [kernel, 'CHECKPOINT_LOCAL_OBSERVER_KERNEL_IPC_POSITIVE__', 'kernel IPC positive marker'],
    [kernel, 'CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__', 'exact fixture cleanup marker'],
    [kernel, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_COMPLETION__', 'durable coordinator completion is emitted only after wrapper validation'],
    [unit, 'ProtectSystem=strict', 'service filesystem restriction'],
    [unit, 'CapabilityBoundingSet=CAP_SYS_PTRACE', 'only authorized fixed read-only proc capability'],
    [unit, 'AmbientCapabilities=CAP_SYS_PTRACE', 'effective fixed read-only proc capability'],
    [unit, 'SystemCallFilter=~ptrace process_vm_writev', 'deny process-control syscalls'],
    [unit, 'Group=vram-governor', 'fixed production observer group'],
    [unit, 'ReadWritePaths=/run/vram-governor-local-observer', 'narrow socket runtime write path'],
  ];
  for (const [source, token, label] of required) assert(source.includes(token), `missing source contract: ${label}`);
  const purePeerTest = sources.get(owned[4]);
  const purePeerStart = purePeerTest.indexOf('func TestCheckpointLocalObserverPeerCredentialAdmission(');
  const purePeerEnd = purePeerTest.indexOf('\nfunc ', purePeerStart + 1);
  assert(purePeerStart >= 0 && purePeerEnd > purePeerStart, 'pure peer credential test boundary is missing');
  const purePeerBody = purePeerTest.slice(purePeerStart, purePeerEnd);
  assert(purePeerBody.includes('const fixtureGID = uint32(988)') && !purePeerBody.includes('LookupGroup'), 'ordinary peer credential test depends on a host group lookup');
  assert(!entry.includes('os.Args') && !entry.includes('os.Getenv'), 'production command entrypoint exposes caller-controlled configuration');
  const exactDirective = (name, expected) => {
    const directives = unit.match(new RegExp(`^${name}=.*$`, 'gm')) ?? [];
    return directives.length === 1 && directives[0] === expected;
  };
  assert(exactDirective('CapabilityBoundingSet', 'CapabilityBoundingSet=CAP_SYS_PTRACE'), 'service capability bounding set is broader, duplicated, or missing');
  assert(exactDirective('AmbientCapabilities', 'AmbientCapabilities=CAP_SYS_PTRACE'), 'service ambient capability set is broader, duplicated, or missing');
  assert(exactDirective('SystemCallFilter', 'SystemCallFilter=~ptrace process_vm_writev'), 'service process-control syscall denylist is missing, duplicated, or changed');
  assert(exactDirective('User', 'User=root') && exactDirective('Group', 'Group=vram-governor'), 'service root/group posture is not exact');
  const normalWslStart = verifier.indexOf('\nfunction wsl(');
  const normalWslEnd = verifier.indexOf('\nfunction wslPath(', normalWslStart + 1);
  const wslPathEnd = verifier.indexOf('\nfunction shellQuote(', normalWslEnd + 1);
  const spawnWslStart = verifier.indexOf('\nfunction spawnWsl(');
  const spawnWslEnd = verifier.indexOf('\nfunction buildLinuxTestCommand(', spawnWslStart + 1);
  const withBinaryStart = verifier.indexOf('\nfunction withLinuxBinary(');
  const withBinaryEnd = verifier.indexOf('\nconst authorityTests =', withBinaryStart + 1);
  assert(normalWslStart >= 0 && normalWslEnd > normalWslStart && wslPathEnd > normalWslEnd &&
    verifier.slice(normalWslStart, normalWslEnd).includes('buildWslArgv(programArgs)') &&
    verifier.slice(normalWslEnd, wslPathEnd).includes("invokeWsl(['wslpath', '-a', localPath])"),
  'normal WSL/path helpers do not use the shared direct-argv builder with distinct wslpath arguments');
  assert(spawnWslStart >= 0 && spawnWslEnd > spawnWslStart && verifier.slice(spawnWslStart, spawnWslEnd).includes('buildWslArgv(programArgs)') &&
    withBinaryStart >= 0 && withBinaryEnd > withBinaryStart && verifier.slice(withBinaryStart, withBinaryEnd).includes("spawnWsl(['bash', '--noprofile', '--norc', '-lc', command], {"),
  'mutant WSL invocation does not use the shared direct-argv builder and fixed Bash shell');
  const withBinary = verifier.slice(withBinaryStart, withBinaryEnd);
  assert(withBinary.includes('const command = buildLinuxTestCommand({ repo, bin, env, timeoutSeconds, runRegex });') &&
    withBinary.includes("const output = wsl(['bash', '--noprofile', '--norc', '-lc', command],"),
  'normal Linux test invocation bypasses the shared quoted command builder or explicit Bash shell');
  const fixtureCleanup = kernel.slice(kernel.indexOf('func checkpointLocalObserverStopFixtureUnit'), kernel.indexOf('func checkpointLocalObserverWaitFixtureUnit'));
  assert(fixtureCleanup.includes('unix.PidfdSendSignal(fixture.pidfd, unix.SIGTERM, nil, 0)') &&
    !fixtureCleanup.includes('systemctl') && !fixtureCleanup.includes('PidfdOpen('), 'fixture cleanup does not rely only on the original held pidfd');
  assert(!linux.includes('CHECKPOINT_LOCAL_OBSERVER_KERNEL'), 'production Linux implementation consults fixture environment');
  assert(!common.includes('caller_pid') && !common.includes('caller_path') && !common.includes('caller_unit'), 'wire schema exposes caller-selected process authority');
  const outerDeathStart = kernel.indexOf('\nfunc checkpointLocalObserverKernelOuterParentDeath(');
  const outerDeathEnd = kernel.indexOf('\nfunc checkpointLocalObserverParentDeathReportValid(', outerDeathStart + 1);
  assert(outerDeathStart >= 0 && outerDeathEnd > outerDeathStart, 'outer-parent death helper boundaries are missing or ambiguous');
  const outerDeath = kernel.slice(outerDeathStart, outerDeathEnd);
  const coordinatorStart = kernel.indexOf('\nfunc checkpointLocalObserverKernelArmParentDeathCoordinator(');
  const coordinatorEnd = kernel.indexOf('\nfunc checkpointLocalObserverKernelRunParentDeathCoordinator(', coordinatorStart + 1);
  assert(coordinatorStart >= 0 && coordinatorEnd > coordinatorStart, 'coordinator arm boundaries are missing or ambiguous');
  const coordinatorArm = kernel.slice(coordinatorStart, coordinatorEnd);
  const coordinatorRunEnd = kernel.indexOf('\nfunc checkpointLocalObserverReadCoordinatorAck(', coordinatorEnd + 1);
  assert(coordinatorEnd >= 0 && coordinatorRunEnd > coordinatorEnd, 'coordinator run boundaries are missing or ambiguous');
  const coordinatorRun = kernel.slice(coordinatorEnd, coordinatorRunEnd);
  for (const [body, token, label] of [
    [outerDeath, 'checkpointLocalObserverReceiveCoordinatorCustody(parentControlSocket, nonce', 'wrapper accepts coordinator custody before parent death'],
    [outerDeath, 'checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD', 'wrapper waits on original coordinator pidfd'],
    [outerDeath, 'checkpointLocalObserverReadCoordinatorCompletion(parentControlSocket, nonce', 'wrapper requires post-fsync completion before artifact cleanup'],
    [outerDeath, 'checkpointLocalObserverReadParentDeathReport(reportFD', 'wrapper reads only the pinned coordinator report'],
    [outerDeath, '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_REPORT__:', 'outer report is emitted only after coordinator terminal confirmation'],
    [coordinatorArm, 'unix.SendmsgN(int(parentSocket.Fd()), custody, unix.UnixRights(coordinatorPIDFD)', 'original coordinator pidfd is transferred with exact nonce-bound custody'],
    [coordinatorRun, 'checkpointLocalObserverWaitPidfdExited(parentPIDFD', 'coordinator independently observes abrupt parent death'],
    [coordinatorRun, 'checkpointLocalObserverStopParentDeathUnit(fixture)', 'coordinator signals only original held unit pidfds'],
    [coordinatorRun, 'file.Sync()', 'coordinator report is durably synced before terminal exit'],
    [coordinatorRun, 'unix.Fsync(reportFD)', 'coordinator report directory entry is durably synced'],
    [coordinatorRun, 'unix.SendmsgN(completionFD, completion, nil, nil, 0)', 'coordinator sends explicit completion only after durable report'],
  ]) assert(body.includes(token), `missing parent-death source contract: ${label}`);
  assert(!outerDeath.includes('Process.Kill(') && !coordinatorRun.includes('systemctl stop'), 'outer-parent proof uses numeric or name-based process cleanup');
  return { sources, linux, common };
}

function assertLocalCollectorRoleRoute(linux) {
  const signature = 'checkpointLocalObserverCollect(ctx context.Context) (CheckpointManagedBinding, error) {';
  const collector = extractGoFunction(linux, signature, 'root collector source assembly');
  assert(collector.includes('nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver') &&
    !collector.includes('nestedFootprint: observeNestedManagedCheckpointFootprint,'),
  'root collector must consume the fixed local-observer role-bound bridge, not the generic root/supervisor route');
  const genericMutant = linux.replace('nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver', 'nestedFootprint: observeNestedManagedCheckpointFootprint');
  assert(genericMutant !== linux, 'generic collector wrapper mutant target is absent');
  assert.throws(() => assertLocalCollectorRoleRoute(genericMutant), /role-bound bridge/,
    'generic fixed-supervisor collector route passed the actual collector predicate');
  assert(!collector.includes('ObserveCheckpointManagedLocalBinding('),
    'root collector must not recursively call the public managed entrypoint');
}

const parentReportMarker = '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_REPORT__:';
const parentNonceMarker = '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_NONCE__:';
const parentCompletionMarker = '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_COMPLETION__';
const parentExitMarker = '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_OUTER_PARENT_DEATH__';
const expectedReportKeys = [
  'version', 'nonce', 'parent_pid', 'parent_start', 'expected_parent_exit', 'parent_death_observed',
  'post_death_live_units', 'original_worker_exited', 'units_absent', 'sentinel_survived', 'sentinel_exited',
  'root_removed', 'sentinel_pid', 'sentinel_start', 'sentinel_cgroup', 'max_live_unit_age_ms', 'unit_roles', 'unit_names',
];

function parseParentDeathReportOutput(output) {
  const lines = output.split(/\r?\n/);
  const reports = lines.filter((line) => line.startsWith(parentReportMarker));
  const nonces = lines.filter((line) => line.startsWith(parentNonceMarker));
  const completions = lines.filter((line) => line === parentCompletionMarker);
  const exits = lines.filter((line) => line === parentExitMarker);
  assert(reports.length === 1 && nonces.length === 1 && completions.length === 1 && exits.length === 1, 'outer-parent proof marker inventory is not exact');
  assert(lines.indexOf(reports[0]) < lines.indexOf(nonces[0]) && lines.indexOf(nonces[0]) < lines.indexOf(completions[0]) && lines.indexOf(completions[0]) < lines.indexOf(exits[0]), 'outer-parent proof markers are reordered');
  const expectedNonce = nonces[0].slice(parentNonceMarker.length);
  assert(/^[0-9a-f]{32}$/.test(expectedNonce), 'outer-parent nonce marker is invalid');
  const encoded = reports[0].slice(parentReportMarker.length);
  assert(/^[A-Za-z0-9+/]+$/.test(encoded), 'parent-death report base64 framing is invalid');
  const bytes = Buffer.from(encoded, 'base64');
  assert(bytes.length > 0 && bytes.length <= 4096 && bytes.toString('base64').replace(/=+$/, '') === encoded, 'parent-death report base64 is noncanonical or outside its bound');
  const text = bytes.toString('utf8');
  assert(Buffer.from(text, 'utf8').equals(bytes), 'parent-death report contains invalid UTF-8');
  const report = JSON.parse(text);
  assert(report && typeof report === 'object' && !Array.isArray(report), 'parent-death report is not an object');
  assert(JSON.stringify(report) === text, 'parent-death report is duplicate-keyed, reordered, or noncanonical JSON');
  assert(JSON.stringify(Object.keys(report)) === JSON.stringify(expectedReportKeys), 'parent-death report schema keys or ordering differ');
  assert(report.version === 1 && /^[0-9a-f]{32}$/.test(report.nonce) && report.nonce === expectedNonce, 'parent-death report version or nonce is invalid');
  assert(Number.isSafeInteger(report.parent_pid) && report.parent_pid > 1 && Number.isSafeInteger(report.parent_start) && report.parent_start > 0, 'parent identity is invalid');
  assert(report.expected_parent_exit === 73 && report.parent_death_observed === true && report.post_death_live_units === 3 && report.original_worker_exited === true, 'parent-death observation or live-unit control is invalid');
  assert(JSON.stringify(report.units_absent) === '[true,true,true,true]' && report.sentinel_survived === true && report.sentinel_exited === true && report.root_removed === true, 'cleanup and unrelated-survival proof is incomplete');
  assert(Number.isSafeInteger(report.sentinel_pid) && report.sentinel_pid > 1 && Number.isSafeInteger(report.sentinel_start) && report.sentinel_start > 0 && typeof report.sentinel_cgroup === 'string' && report.sentinel_cgroup.length > 0, 'outside sentinel identity is invalid');
  assert(Number.isSafeInteger(report.max_live_unit_age_ms) && report.max_live_unit_age_ms > 0 && report.max_live_unit_age_ms <= 150000, 'unit-expiry margin is invalid');
  assert(JSON.stringify(report.unit_roles) === JSON.stringify(['original-worker', 'replacement-worker', 'unrelated-control', 'broker']), 'unit role inventory is invalid');
  assert(Array.isArray(report.unit_names) && report.unit_names.length === 4 && report.unit_names.every((name) => typeof name === 'string' && /^checkpoint-local-observer-fixture-[A-Za-z0-9_.@:-]+\.service$/.test(name)) && new Set(report.unit_names).size === 4, 'unit name inventory is invalid');
  return report;
}

function selfTestParentDeathReportParser() {
  const report = {
    version: 1, nonce: '0123456789abcdef0123456789abcdef', parent_pid: 101, parent_start: 202,
    expected_parent_exit: 73, parent_death_observed: true, post_death_live_units: 3,
    original_worker_exited: true, units_absent: [true, true, true, true], sentinel_survived: true,
    sentinel_exited: true, root_removed: true, sentinel_pid: 303, sentinel_start: 404,
    sentinel_cgroup: '/user.slice/test.scope', max_live_unit_age_ms: 1200,
    unit_roles: ['original-worker', 'replacement-worker', 'unrelated-control', 'broker'],
    unit_names: ['checkpoint-local-observer-fixture-a.service', 'checkpoint-local-observer-fixture-b.service', 'checkpoint-local-observer-fixture-c.service', 'checkpoint-local-observer-fixture-d.service'],
  };
  const encoded = Buffer.from(JSON.stringify(report)).toString('base64').replace(/=+$/, '');
  const valid = `noise\n${parentReportMarker}${encoded}\n${parentNonceMarker}${report.nonce}\n${parentCompletionMarker}\n${parentExitMarker}\n`;
  assert(parseParentDeathReportOutput(valid).nonce === report.nonce, 'valid parent-death report was rejected');
  const frame = (value, options = {}) => `${options.reports ?? `${parentReportMarker}${Buffer.from(value).toString('base64').replace(/=+$/, '')}\n`}${options.nonce ?? `${parentNonceMarker}${report.nonce}\n`}${options.completion ?? `${parentCompletionMarker}\n`}${options.exit ?? `${parentExitMarker}\n`}`;
  const jsonFrame = (value) => frame(JSON.stringify(value));
  const negatives = [
    ['missing report', `${parentExitMarker}\n`],
    ['duplicate report', `${valid}${parentReportMarker}${encoded}\n`],
    ['missing nonce marker', frame(JSON.stringify(report), { nonce: '' })],
    ['missing completion marker', frame(JSON.stringify(report), { completion: '' })],
    ['duplicate completion marker', `${valid}${parentCompletionMarker}\n`],
    ['missing exit marker', frame(JSON.stringify(report), { exit: '' })],
    ['duplicate exit marker', `${valid}${parentExitMarker}\n`],
    ['partial base64', frame('', { reports: `${parentReportMarker}${encoded.slice(0, -1)}!\n` })],
    ['wrong nonce', frame(JSON.stringify({ ...report, nonce: 'f'.repeat(32) }))],
    ['unexpected report event', `${valid}__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_REPORT__:e30\n`],
    ['duplicate JSON key', frame(JSON.stringify(report).replace('"version":1', '"version":1,"version":1'))],
    ['reordered keys', frame(JSON.stringify(Object.fromEntries(Object.entries(report).reverse())))],
    ['failed cleanup', jsonFrame({ ...report, units_absent: [true, false, true, true] })],
    ['unexpected field', jsonFrame({ ...report, surprise: true })],
    ['reordered markers', `${parentReportMarker}${encoded}\n${parentCompletionMarker}\n${parentNonceMarker}${report.nonce}\n${parentExitMarker}\n`],
  ];
  const invalidUTF8 = Buffer.from(JSON.stringify(report));
  const cgroupOffset = invalidUTF8.indexOf(Buffer.from(report.sentinel_cgroup));
  invalidUTF8[cgroupOffset] = 0xff;
  negatives.push(['invalid UTF-8', `${parentReportMarker}${invalidUTF8.toString('base64').replace(/=+$/, '')}\n${parentNonceMarker}${report.nonce}\n${parentCompletionMarker}\n${parentExitMarker}\n`]);
  for (const [label, output] of negatives) {
    let rejection;
    try { parseParentDeathReportOutput(output); } catch (error) { rejection = error; }
    assert(rejection, `parent-death report parser accepted ${label}`);
    if (label === 'reordered markers') {
      assert(rejection.message === 'outer-parent proof markers are reordered', 'reordered-marker control failed for an unrelated parser condition');
    }
  }
}

function selfTestParentDeathSourceControls(kernel) {
  const extractArm = (source) => {
    const start = source.indexOf('\nfunc checkpointLocalObserverKernelArmParentDeathCoordinator(');
    const end = source.indexOf('\nfunc checkpointLocalObserverKernelRunParentDeathCoordinator(', start + 1);
    assert(start >= 0 && end > start, 'coordinator arm declaration is missing or ambiguous');
    return source.slice(start, end);
  };
  const required = 'unix.SendmsgN(int(parentSocket.Fd()), custody, unix.UnixRights(coordinatorPIDFD)';
  assert(extractArm(kernel).includes(required), 'coordinator custody transfer is missing');
  const mutant = kernel.replace(required, 'unix.SendmsgN(int(parentSocket.Fd()), custody, nil');
  assert(mutant !== kernel && !extractArm(mutant).includes(required), 'missing original-pidfd transfer mutant was not exercised');
  const outerStart = kernel.indexOf('\nfunc checkpointLocalObserverKernelOuterParentDeath(');
  const outerEnd = kernel.indexOf('\nfunc checkpointLocalObserverParentDeathReportValid(', outerStart + 1);
  assert(outerStart >= 0 && outerEnd > outerStart, 'outer-parent declaration is missing or ambiguous');
  const outer = kernel.slice(outerStart, outerEnd);
  assert(outer.includes('checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD'), 'wrapper terminal-coordinator barrier is missing');
  assert(outer.includes('checkpointLocalObserverReadCoordinatorCompletion(parentControlSocket, nonce'), 'wrapper completion-packet requirement is missing');
  const noBarrier = kernel.replace('checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD, 78*time.Second)', 'nil');
  const noBarrierOuter = noBarrier.slice(noBarrier.indexOf('\nfunc checkpointLocalObserverKernelOuterParentDeath('), noBarrier.indexOf('\nfunc checkpointLocalObserverParentDeathReportValid('));
  assert(!noBarrierOuter.includes('checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD'), 'missing coordinator-terminal barrier mutant was not refuted');
  const runStart = kernel.indexOf('\nfunc checkpointLocalObserverKernelRunParentDeathCoordinator(');
  const runEnd = kernel.indexOf('\nfunc checkpointLocalObserverReadCoordinatorAck(', runStart + 1);
  assert(runStart >= 0 && runEnd > runStart, 'coordinator completion declaration boundary is missing');
  const runBody = kernel.slice(runStart, runEnd);
  const fsyncToken = 'unix.Fsync(reportFD)';
  const completionToken = 'unix.SendmsgN(completionFD, completion, nil, nil, 0)';
  assert(runBody.includes(fsyncToken) && runBody.includes(completionToken), 'durable completion implementation is missing');
  assert(runBody.indexOf('file.Sync()') < runBody.indexOf('file.Close()') && runBody.indexOf('file.Close()') < runBody.indexOf(fsyncToken) && runBody.indexOf(fsyncToken) < runBody.indexOf(completionToken), 'coordinator completion is not ordered after file and directory durability');
  const noDirectorySync = runBody.replace(fsyncToken, '/* sync omitted */');
  assert(!noDirectorySync.includes(fsyncToken), 'missing report-directory-sync mutant was not exercised');
  const noCompletion = runBody.replace(completionToken, '/* completion omitted */');
  assert(!noCompletion.includes(completionToken), 'missing completion-packet mutant was not exercised');
}

function assertSearchOnlyTrustRootSource(linux) {
  const start = linux.indexOf('\nfunc checkpointLocalObserverOpenAbsoluteDirectory(');
  const end = linux.indexOf('\nfunc ', start + 1);
  assert(start >= 0 && end > start, 'trust-root source-control target is missing or ambiguous');
  const body = linux.slice(start, end);
  const open = 'unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW';
  assert((body.match(/unix\.O_PATH\|unix\.O_DIRECTORY\|unix\.O_CLOEXEC\|unix\.O_NOFOLLOW/g) ?? []).length === 2 &&
    body.includes(`unix.Open("/", ${open}, 0)`) && body.includes(`unix.Openat(fd, component, ${open}, 0)`) &&
    !body.includes('unix.O_RDONLY') && body.includes('unix.Fstat(next, &held)') &&
    body.includes('unix.Lstat(current, &named)') && body.includes('held.Dev != named.Dev || held.Ino != named.Ino'),
  'search-only trust root lacks exact O_PATH traversal or held/named identity comparison');
  const leafStart = linux.indexOf('\nfunc checkpointLocalObserverReadRootFile(');
  const leafEnd = linux.indexOf('\nfunc ', leafStart + 1);
  assert(leafStart >= 0 && leafEnd > leafStart && linux.slice(leafStart, leafEnd).includes('unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)'),
    'public-key leaf no longer uses O_RDONLY|O_NOFOLLOW');
}

function selfTestSearchOnlyTrustRootControls(linux) {
  assertSearchOnlyTrustRootSource(linux);
  const open = 'unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW';
  assert(linux.split(open).length - 1 === 2, 'trust-root O_RDONLY mutant target count is not exactly two directory opens');
  const mutant = linux.replaceAll(open, 'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW');
  assert(mutant !== linux, 'compiled O_RDONLY trust-root mutant could not be constructed');
  assert.throws(() => assertSearchOnlyTrustRootSource(mutant), undefined, 'O_RDONLY trust-root mutant passed the same source-control predicate');
  const leafMutant = linux.replace('unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)', 'unix.Open(path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)');
  assert(leafMutant !== linux, 'final-leaf access mutant could not be constructed');
  assert.throws(() => assertSearchOnlyTrustRootSource(leafMutant), undefined, 'non-readable final-leaf mutant passed the same source-control predicate');
}

function assertKernelSearchRootFixtureContract(kernel) {
  const start = kernel.indexOf('\nfunc checkpointLocalObserverKernelFixtureBody(');
  const end = kernel.indexOf('\nfunc ', start + 1);
  assert(start >= 0 && end > start, 'kernel fixture body boundary is missing or ambiguous');
  const body = kernel.slice(start, end);
  const positive = body.indexOf('"public-key-read-positive"');
  const noSearch = body.indexOf('os.Chmod(root, 0700)');
  const wrongGroup = body.indexOf('os.Chown(publicPath, 0, int(wrongGID))');
  const wrongMode = body.indexOf('os.Chmod(publicPath, 0600)');
  const parentSubstitution = body.indexOf('os.Symlink(root, alias)');
  assert(positive >= 0 && noSearch > positive && wrongGroup > noSearch && wrongMode > wrongGroup && parentSubstitution > wrongMode,
    'search-only public-key positive must precede bounded search, group, mode, and parent-symlink negative controls');
  assertKernelParentAliasCleanup(kernel, body);
  for (const marker of [
    '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__',
    '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_ROOT_SEARCH_DENIED__',
    '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_GROUP_DENIED__',
    '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_MODE_DENIED__',
    '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_SUBSTITUTION_DENIED__',
  ]) assert(body.includes(marker), `kernel fixture omitted exact permission event ${marker}`);
  const child = kernel.slice(kernel.indexOf('\nfunc TestCheckpointLocalObserverKernelClientChild('), kernel.indexOf('\nfunc TestCheckpointLocalObserverKernelWorkerChild('));
  assert(child.includes('role == "public-key-read-positive"') && child.includes('role == "public-key-permission-denied"') &&
    child.includes('checkpointLocalObserverReadPublicKey(config)') && child.includes('rootInfo.Mode().Perm() != 0711') &&
    child.includes('rootStat.Uid != 0') && child.includes('pin.uid != 0') && child.includes('pin.gid != checkpointLocalObserverExpectedGroup(config.nodeGroup)') &&
    child.includes('pin.mode != 0640') && child.includes('pin.stat.Nlink != 1') && child.includes('__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_READ_POSITIVE__') &&
    child.includes('__CHECKPOINT_LOCAL_OBSERVER_PUBLIC_KEY_PERMISSION_DENIED__'),
  'permission child does not prove exact unprivileged root/key metadata and denial behavior');
  assert(body.includes('__CHECKPOINT_LOCAL_OBSERVER_KERNEL_KEY_SUBSTITUTION_DENIED__'), 'existing leaf substitution denial was removed');
}

function extractGoFunction(source, signature, label) {
  const start = source.indexOf(`\nfunc ${signature}`);
  const end = source.indexOf('\nfunc ', start + 1);
  assert(start >= 0 && end > start, `${label}: Go function boundary is missing or ambiguous`);
  return source.slice(start, end);
}

function assertParentFailureSiteInventory(kernel) {
  const siteStart = kernel.indexOf('\nfunc checkpointLocalObserverParentFailureSite(lineNumber int) string {');
  assert(siteStart >= 0 && kernel.indexOf('\nfunc ', siteStart + 1) < 0, 'parent failure site allowlist is not the fixed final source function');
  const sites = kernel.slice(siteStart);
  const match = sites.match(/\n\tcase ([0-9, ]+):\n/);
  assert(match, 'fixed parent failure assertion-site allowlist is missing');
  const allowed = match[1].split(',').map((value) => Number(value.trim()));
  assert(allowed.every(Number.isSafeInteger) && new Set(allowed).size === allowed.length && allowed.every((value, index) => index === 0 || allowed[index - 1] < value),
    'parent failure assertion-site allowlist is not finite, unique, and ordered');
  const routeStart = kernel.indexOf('\nconst (\n\tcheckpointObserverRouteOptInEnv');
  const routeEnd = kernel.indexOf('\nfunc checkpointLocalObserverKernelFixtureBody', routeStart);
  assert(routeStart >= 0 && routeEnd > routeStart, 'composed route fixture source region is not uniquely bounded');
  const routeStartLine = kernel.slice(0, routeStart).split(/\r?\n/).length;
  const routeEndLine = kernel.slice(0, routeEnd).split(/\r?\n/).length;
  const actual = [];
  for (const [index, line] of kernel.split(/\r?\n/).entries()) {
    if (index + 1 >= routeStartLine && index + 1 < routeEndLine) continue;
    if (/\bt\.(?:Fatalf?|Errorf?)\s*\(/.test(line)) actual.push(index + 1);
  }
  if (allowed.length !== actual.length || allowed.some((line, index) => line !== actual[index])) {
    throw new Error('parent failure allowlist is not exactly derived from the owned tagged-fixture assertion sites');
  }
  return actual;
}

function assertParentFailureClassifierFixtureControls(kernel, siteLines) {
  const top = extractGoFunction(kernel, 'TestCheckpointLocalObserverKernelFixture(t *testing.T) {', 'inventoried kernel top fixture');
  const helper = extractGoFunction(kernel, 'checkpointLocalObserverParentFailureClassifierControls(t *testing.T) {', 'parent failure classifier Go controls');
  const positiveSite = helper.match(/const positiveSite = ([0-9]+)/);
  assert(positiveSite && siteLines.includes(Number(positiveSite[1])), 'Go classifier positive control does not use a real allowlisted assertion site');
  assert(top.indexOf('checkpointLocalObserverParentFailureClassifierControls(t)') >= 0 &&
    top.indexOf('checkpointLocalObserverParentFailureClassifierControls(t)') < top.indexOf('checkpointLocalObserverKernelFixtureBody(t, true)'),
  'real classifier table is not exercised within the existing inventoried top fixture');
  assert(!helper.includes('t.Run('), 'classifier controls added a new RUN name');
  const labels = [...helper.matchAll(/name:\s*"([^"]+)"/g)].map((entry) => entry[1]);
  assert.deepEqual(labels, [
    'failed parent with earlier decoy', 'wrong owner', 'malformed failure header', 'missing failure header', 'earlier decoy only', 'unknown source site',
    'duplicate failure headers', 'duplicate source sites', 'malformed source line', 'wrong source file',
    'empty capture', 'hostile text remains private', 'capture overflow',
  ], 'actual Go classifier table does not cover the ordered positive and fail-closed controls');
  assert(helper.indexOf('failed parent with earlier decoy') < helper.indexOf('wrong owner') &&
    helper.includes('checkpointLocalObserverParentFailureClass(capture)') &&
    helper.includes('strings.Repeat("x", checkpointLocalObserverParentOutputLimit+1)'),
  'actual Go classifier positive does not precede its negative and overflow controls');
  return true;
}

function assertOuterFailureDiagnosticSource(kernel) {
  assert(/checkpointLocalObserverParentOutputLimit\s*=\s*8 \* 1024\r?\n/.test(kernel), 'parent output capture is not fixed at the 8 KiB bound');
  assert(kernel.split(/\r?\n/).length <= 4800, 'owned kernel fixture grew beyond the explicit 4,800-line classifier source bound');
  const captureTypeStart = kernel.indexOf('\ntype checkpointLocalObserverParentOutputCapture struct {');
  const captureTypeEnd = kernel.indexOf('\nfunc ', captureTypeStart + 1);
  assert(captureTypeStart >= 0 && captureTypeEnd > captureTypeStart, 'bounded parent output capture type is missing');
  const captureType = kernel.slice(captureTypeStart, captureTypeEnd);
  assert(captureType.includes('mu       sync.Mutex') && captureType.includes('data     []byte') && captureType.includes('total    uint64') && captureType.includes('overflow bool'),
    'parent output capture lacks mutex-protected bounded bytes, full-write accounting, or overflow state');
  const writer = extractGoFunction(kernel, '(capture *checkpointLocalObserverParentOutputCapture) Write(p []byte) (int, error) {', 'bounded output writer');
  const overflowEnd = writer.indexOf('} else if len(p) != 0 {');
  const fullWriteReturn = writer.indexOf('return len(p), nil', overflowEnd + 1);
  const partialOverflow = 'if writeCount != len(p) {\n\t\t\tcapture.overflow = true\n\t\t}';
  assert(writer.includes('capture.mu.Lock()') && writer.includes('defer capture.mu.Unlock()') &&
    writer.includes('checkpointLocalObserverParentOutputLimit - len(capture.data)') &&
    writer.includes(partialOverflow) && overflowEnd >= 0 && fullWriteReturn > overflowEnd,
  'parent writer does not lock, cap/discard overflow, or return the full write count');
  const classifier = extractGoFunction(kernel, 'checkpointLocalObserverParentFailureClass(capture *checkpointLocalObserverParentOutputCapture) string {', 'bounded output classifier');
  assert(classifier.includes('if overflow || total > checkpointLocalObserverParentOutputLimit') &&
    classifier.includes('return "overflow"') && classifier.includes('return "unavailable"') &&
    classifier.includes('const source = "checkpoint_local_observer_kernel_linux_test.go:"') &&
    classifier.includes('checkpointLocalObserverParentFailureHeader(line)') &&
    classifier.includes('if failureHeader < 0') &&
    classifier.includes('strings.HasPrefix(line, prefix)') &&
    classifier.includes('checkpointLocalObserverParentFailureSite(lineNumber)') &&
    classifier.includes('failureHeader >= 0') && classifier.includes('site == "" || found != ""') &&
    classifier.includes('separator := strings.Index(location, ": ")') &&
    !classifier.includes('lineNumber <= 3000') && !/fmt\.(?:Print|Fprint)/.test(classifier),
  'parent failure classifier lacks exact owner, anchored failure-line, fixed site, ambiguity, or privacy guards');
  const header = extractGoFunction(kernel, 'checkpointLocalObserverParentFailureHeader(line string) bool {', 'exact failed-test header parser');
  assert(header.includes('--- FAIL: TestCheckpointLocalObserverKernelFixture (') &&
    header.includes('strings.HasPrefix(line, prefix)') && header.includes('strings.HasSuffix(line, "s)")') &&
    header.includes('strings.Count(duration, ".") > 1') && header.includes('duration[len(duration)-1] == \'.\''),
  'classifier does not require the exact anchored failed top-test header');
  const siteLines = assertParentFailureSiteInventory(kernel);
  const arbitraryRange = replaceGoFunction(kernel, 'checkpointLocalObserverParentFailureSite(lineNumber int) string {',
    'case 245,', 'case 1, 2, 3, 4, 5, 245,', 'parent failure site arbitrary-range mutant');
  let arbitraryRangeFailure;
  try { assertParentFailureSiteInventory(arbitraryRange); } catch (error) { arbitraryRangeFailure = error; }
  assert(arbitraryRangeFailure instanceof Error && arbitraryRangeFailure.message === 'parent failure allowlist is not exactly derived from the owned tagged-fixture assertion sites',
    'arbitrary-range mutant did not fail the exact derived assertion-site inventory predicate');
  assertParentFailureClassifierFixtureControls(kernel, siteLines);
  const terminal = extractGoFunction(kernel, 'checkpointLocalObserverParentTerminalClass(pidfd int) string {', 'parent terminal observer');
  assert(terminal.includes('checkpointLocalPIDFDAlive(pidfd)') && terminal.includes('return "live"') &&
    terminal.includes('return "terminal"') && terminal.includes('return "unavailable"') &&
    !terminal.includes('Wait(') && !terminal.includes('PidfdSendSignal') && !terminal.includes('PidfdOpen'),
  'parent status observation does not use only the original held pidfd as a non-signaling observation');
  const custodyClass = extractGoFunction(kernel, 'checkpointLocalObserverCustodyFailureClass(err error) string {', 'custody failure classifier');
  for (const token of [
    'checkpointLocalObserverCustodyEmpty', 'return "empty"',
    'checkpointLocalObserverCustodyPayloadTruncated', 'return "payload_truncated"',
    'checkpointLocalObserverCustodyAncillaryTruncated', 'return "ancillary_truncated"',
    'checkpointLocalObserverCustodyPayloadFull', 'return "payload_full"',
    'checkpointLocalObserverCustodyReceiverTimeout', 'return "receiver_timeout"',
    'checkpointLocalObserverCustodyReceiverUnavailable', 'return "receiver_unavailable"',
    'return "custody_rejected"',
  ]) assert(custodyClass.includes(token), `finite custody failure classification omitted ${token}`);
  const receiver = extractGoFunction(kernel, 'checkpointLocalObserverReceiveCoordinatorCustody(file *os.File, nonce string, timeout time.Duration) (int, int, uint64, error) {', 'custody receiver');
  assertPollInterruptRetrySource(kernel);
  const payloadTruncatedAt = receiver.indexOf('flags&unix.MSG_TRUNC != 0');
  const ancillaryTruncatedAt = receiver.indexOf('flags&unix.MSG_CTRUNC != 0');
  const emptyAt = receiver.indexOf('if n == 0');
  const fullAt = receiver.indexOf('if n == len(payload)');
  assert(payloadTruncatedAt >= 0 && ancillaryTruncatedAt > payloadTruncatedAt && emptyAt > ancillaryTruncatedAt && fullAt > emptyAt &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyPayloadTruncated)') &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyAncillaryTruncated)') &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyEmpty)') &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyPayloadFull)') &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyReceiverTimeout)') &&
    receiver.includes('errors.New(checkpointLocalObserverCustodyReceiverUnavailable)'),
  'custody receiver does not distinguish empty, payload truncation, ancillary truncation, payload-full, and unavailable/timeout outcomes');
  const outer = extractGoFunction(kernel, 'checkpointLocalObserverKernelOuterParentDeath(t *testing.T) {', 'outer-parent wrapper');
  const failureStart = outer.indexOf('if custodyErr != nil || coordinatorPID <= 1 || coordinatorStart == 0 {');
  const failureEnd = outer.indexOf('\n\tparentErr := parent.Wait()', failureStart + 1);
  assert(failureStart >= 0 && failureEnd > failureStart, 'custody failure branch no longer precedes the original parent wait');
  const failure = outer.slice(failureStart, failureEnd);
  assert(outer.includes('parent.Stdout, parent.Stderr = parentOutput, parentOutput') &&
    outer.includes('checkpointLocalObserverParentOutputCapture{}') &&
    outer.includes('checkpointLocalObserverReceiveCoordinatorCustody(parentControlSocket, nonce, 140*time.Second)') &&
    failure.includes('checkpointLocalObserverCustodyFailureClass(custodyErr)') &&
    failure.includes('checkpointLocalObserverParentFailureClass(parentOutput)') &&
    failure.includes('checkpointLocalObserverParentTerminalClass(parentPIDFD)') &&
    failure.includes('t.Logf("__CHECKPOINT_LOCAL_OBSERVER_PARENT_FAILURE__ reason=%s parent=%s status=%s"') &&
    failure.includes('t.Fatalf("coordinator pidfd custody was not transferred; preserving report and bounded fixture children (%s)", reason)') &&
    !failure.includes('%v') &&
    !failure.includes('parent.Wait()') && !failure.includes('PidfdSendSignal') && !failure.includes('PidfdOpen'),
  'bounded diagnostics are not confined to the existing failure branch or alter custody/cleanup authority');
  assert(outer.includes('parent.Wait()') && outer.indexOf('parent.Wait()') > failureEnd &&
    outer.includes('checkpointLocalObserverWaitPidfdExited(coordinatorPIDFD, 78*time.Second)'),
  'diagnostic change removed the existing later wait or coordinator terminal barrier');
}

function assertPollInterruptRetrySource(kernel) {
  const receiver = extractGoFunction(kernel, 'checkpointLocalObserverReceiveCoordinatorCustody(file *os.File, nonce string, timeout time.Duration) (int, int, uint64, error) {', 'custody receiver');
  const ack = extractGoFunction(kernel, 'checkpointLocalObserverReadCoordinatorAck(file *os.File, nonce string, timeout time.Duration) error {', 'coordinator ACK wait');
  const completion = extractGoFunction(kernel, 'checkpointLocalObserverReadCoordinatorCompletion(file *os.File, nonce string, timeout time.Duration) error {', 'coordinator completion wait');
  const pidfd = extractGoFunction(kernel, 'checkpointLocalObserverWaitPidfdExited(pidfd int, timeout time.Duration) error {', 'held pidfd wait');
  const predicate = extractGoFunction(kernel, 'checkpointLocalObserverPollInterrupted(err error) bool {', 'poll interruption predicate');
  const controls = extractGoFunction(kernel, 'checkpointLocalObserverPollInterruptControls(t *testing.T) {', 'poll interruption controls');
  const classifierControls = extractGoFunction(kernel, 'checkpointLocalObserverParentFailureClassifierControls(t *testing.T) {', 'existing in-inventory test control hook');
  const top = extractGoFunction(kernel, 'TestCheckpointLocalObserverKernelFixture(t *testing.T) {', 'inventoried kernel top fixture');
  const retryBranch = 'if err != nil {\n\t\t\tif checkpointLocalObserverPollInterrupted(err) {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\treturn err\n\t\t}';
  const receiverRetryBranch = /if err != nil \{\r?\n\t\t\tif checkpointLocalObserverPollInterrupted\(err\) \{\r?\n\t\t\t\tcontinue\r?\n\t\t\t\}\r?\n\t\t\treturn -1, 0, 0, errors\.New\(checkpointLocalObserverCustodyReceiverUnavailable\)\r?\n\t\t\}/;
  assert(predicate.includes('return errors.Is(err, unix.EINTR)') && !predicate.includes('err == nil') &&
    receiverRetryBranch.test(receiver), 'custody receiver does not retry only wrapped or direct EINTR before its unchanged unavailable return');
  const boundedWaits = [
    { name: 'ACK', source: ack, readiness: 'if ready == 0 {', path: [
      'poll[0].Revents&(unix.POLLERR|unix.POLLNVAL|unix.POLLHUP)', 'unix.Read(int(file.Fd()), buffer)', 'if count == 0 || count == len(buffer)', 'if string(buffer[:count]) !=',
    ] },
    { name: 'completion', source: completion, readiness: 'if ready == 0 {', path: [
      'unix.Recvmsg(', 'if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR)', 'flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC)', 'string(payload[:n]) != "COMPLETE:"+nonce',
    ] },
    { name: 'pidfd', source: pidfd, readiness: 'if ready == 0 {', path: [
      'poll[0].Revents&(unix.POLLERR|unix.POLLNVAL)', 'if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {\n\t\t\treturn nil',
    ] },
  ];
  for (const wait of boundedWaits) {
    const source = wait.source;
    const deadlineAt = source.indexOf('deadline := time.Now().Add(timeout)');
    const loopAt = source.indexOf('for time.Now().Before(deadline) {');
    const pollAt = source.indexOf('ready, err := unix.Poll(poll, 25)');
    const errorAt = source.indexOf(retryBranch);
    const readinessAt = source.indexOf(wait.readiness);
    const pathAt = wait.path.map((part) => source.indexOf(part, readinessAt));
    assert(deadlineAt >= 0 && loopAt > deadlineAt && pollAt > loopAt && errorAt > pollAt && readinessAt > errorAt &&
      source.split('deadline := time.Now().Add(timeout)').length === 2 && source.split('unix.Poll(poll, 25)').length === 2 &&
      source.split(retryBranch).length === 2 && pathAt.every((at) => at > readinessAt) &&
      pathAt.every((at, index) => index === 0 || at > pathAt[index - 1]) &&
      (wait.name !== 'ACK' || (source.includes('ARMED:') && source.includes('nonce+')) ) &&
      !/deadline\s*=[^=]/.test(source) && !/ready\s*=[^=]/.test(source) && !source.includes('Revents ='),
    `${wait.name} wait changed its single deadline, 25ms Poll, exact EINTR-only branch, or original readiness path`);
  }
  const receiverDeadlineAt = receiver.indexOf('deadline := time.Now().Add(timeout)');
  const receiverLoopAt = receiver.indexOf('for time.Now().Before(deadline) {');
  const receiverPollAt = receiver.indexOf('ready, err := unix.Poll(poll, 25)');
  const receiverReadyAt = receiver.indexOf('if ready == 0 {');
  const receiverRecvAt = receiver.indexOf('unix.Recvmsg(');
  assert(receiverDeadlineAt >= 0 && receiverLoopAt > receiverDeadlineAt && receiverPollAt > receiverLoopAt && receiverReadyAt > receiverPollAt && receiverRecvAt > receiverReadyAt &&
    receiver.split('deadline := time.Now().Add(timeout)').length === 2 && receiver.split('unix.Poll(poll, 25)').length === 2 &&
    !/deadline\s*=[^=]/.test(receiver) && !/ready\s*=[^=]/.test(receiver) && !receiver.includes('Revents ='),
  'custody retry changed the existing single deadline, 25ms Poll bound, or readiness path');
  const labels = [...controls.matchAll(/name:\s*"([^"]+)"/g)].map((entry) => entry[1]);
  assert.deepEqual(labels, ['interrupted poll', 'wrapped interrupted poll', 'nil poll error', 'would block poll', 'bad descriptor poll', 'unknown poll error'],
    'actual in-inventory table is missing an ordered known-positive or fail-closed error case');
  assert(controls.includes('checkpointLocalObserverPollInterrupted(test.err)') && controls.includes('wantRetry: true') &&
    controls.includes('unix.EAGAIN') && controls.includes('unix.EBADF') && controls.includes('errors.New("unknown poll failure")'),
  'actual in-inventory table does not exercise direct/wrapped EINTR before nil and non-EINTR negatives');
  assert(classifierControls.includes('checkpointLocalObserverPollInterruptControls(t)') &&
    top.includes('checkpointLocalObserverParentFailureClassifierControls(t)') && !top.includes('t.Run('),
  'poll retry controls are not connected through the already inventoried kernel top test');
}

function selfTestPollInterruptRetryControls(kernel) {
  assertPollInterruptRetrySource(kernel);
  const waitSpecs = [
    ['ACK', 'checkpointLocalObserverReadCoordinatorAck(file *os.File, nonce string, timeout time.Duration) error {'],
    ['completion', 'checkpointLocalObserverReadCoordinatorCompletion(file *os.File, nonce string, timeout time.Duration) error {'],
    ['pidfd', 'checkpointLocalObserverWaitPidfdExited(pidfd int, timeout time.Duration) error {'],
  ];
  const receiverSignature = 'checkpointLocalObserverReceiveCoordinatorCustody(file *os.File, nonce string, timeout time.Duration) (int, int, uint64, error) {';
  const predicateSignature = 'checkpointLocalObserverPollInterrupted(err error) bool {';
  const branch = 'if err != nil {\n\t\t\tif checkpointLocalObserverPollInterrupted(err) {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\treturn err\n\t\t}';
  const receiverRetry = 'if checkpointLocalObserverPollInterrupted(err) {\n\t\t\t\tcontinue\n\t\t\t}';
  const receiverBranch = 'if err != nil {\n\t\t\tif checkpointLocalObserverPollInterrupted(err) {\n\t\t\t\tcontinue\n\t\t\t}\n\t\t\treturn -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverUnavailable)\n\t\t}';
  const fabricatedFallthrough = (failure) => `if err != nil {\n\t\t\tif checkpointLocalObserverPollInterrupted(err) {\n\t\t\t\tpoll[0].Revents = unix.POLLIN\n\t\t\t\tready = 1\n\t\t\t} else {\n\t\t\t\t${failure}\n\t\t\t}\n\t\t}`;
  const mutants = [
    ['custody EINTR retry omitted', replaceGoFunction(kernel, receiverSignature, receiverRetry, 'if false {\n\t\t\t\tcontinue\n\t\t\t}', 'custody receiver')],
    ['all poll errors retried', replaceGoFunction(kernel, predicateSignature, 'return errors.Is(err, unix.EINTR)', 'return err != nil', 'poll interruption predicate')],
    ['custody deadline reset per loop', replaceGoFunction(kernel, receiverSignature, 'for time.Now().Before(deadline) {', 'for time.Now().Before(time.Now().Add(timeout)) {', 'custody receiver')],
    ['custody Poll timeout broadened', replaceGoFunction(kernel, receiverSignature, 'unix.Poll(poll, 25)', 'unix.Poll(poll, 25000)', 'custody receiver')],
  ];
  for (const [name, signature] of waitSpecs) {
    const source = extractGoFunction(kernel, signature, `${name} wait`);
    mutants.push([`${name} EINTR retry omitted`, replaceGoFunction(kernel, signature, branch, 'if err != nil {\n\t\t\treturn err\n\t\t}', `${name} wait`)]);
    mutants.push([`${name} deadline reset per loop`, replaceGoFunction(kernel, signature, 'for time.Now().Before(deadline) {', 'for time.Now().Before(time.Now().Add(timeout)) {', `${name} wait`)]);
    mutants.push([`${name} Poll timeout broadened`, replaceGoFunction(kernel, signature, 'unix.Poll(poll, 25)', 'unix.Poll(poll, 25000)', `${name} wait`)]);
    const after = name === 'ACK' ? 'unix.Read(int(file.Fd()), buffer)' : name === 'completion' ? 'unix.Recvmsg(' : 'if poll[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {\n\t\t\treturn nil';
    const fake = fabricatedFallthrough('return err');
    const readinessMutant = replaceGoFunction(kernel, signature, branch, fake, `${name} wait`);
    const changed = extractGoFunction(readinessMutant, signature, `${name} fabricated-readiness mutant`);
    const branchAt = changed.indexOf(fake);
    const interruptedAt = changed.indexOf('if checkpointLocalObserverPollInterrupted(err) {', branchAt);
    const elseAt = changed.indexOf('} else {', interruptedAt);
    const branchEnd = changed.indexOf('\n\t\t}', elseAt);
    const readinessAt = changed.indexOf('if ready == 0 {', branchAt);
    const afterAt = changed.indexOf(after, readinessAt);
    assert(branchAt >= 0 && interruptedAt > branchAt && elseAt > interruptedAt && branchEnd > elseAt &&
      !changed.slice(interruptedAt, elseAt).includes('continue') && !changed.slice(interruptedAt, elseAt).includes('return') &&
      changed.slice(interruptedAt, elseAt).includes('poll[0].Revents = unix.POLLIN') && changed.slice(interruptedAt, elseAt).includes('ready = 1') &&
      changed.slice(elseAt, branchEnd).includes('return err') && readinessAt > branchAt && afterAt > readinessAt,
    `${name} fabricated-readiness mutant must reach its actual read/receive/terminal-ready path and preserve other errors`);
    let rejected = false;
    try { assertPollInterruptRetrySource(readinessMutant); } catch { rejected = true; }
    assert(rejected, `actual source predicate accepted ${name} fabricated-readiness mutant`);
  }
  for (const [label, mutant] of mutants) {
    assert(mutant !== kernel, `${label} mutant target is absent`);
    assert.throws(() => assertPollInterruptRetrySource(mutant), undefined, `${label} mutant passed the actual receiver source predicate`);
  }
  const receiverFake = fabricatedFallthrough('return -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverUnavailable)');
  const receiverMutant = replaceGoFunction(kernel, receiverSignature, receiverBranch, receiverFake, 'custody receiver');
  const mutantReceiver = extractGoFunction(receiverMutant, receiverSignature, 'custody fabricated-readiness mutant');
  const branchAt = mutantReceiver.indexOf(receiverFake);
  const interruptedAt = mutantReceiver.indexOf('if checkpointLocalObserverPollInterrupted(err) {', branchAt);
  const nonInterruptedAt = mutantReceiver.indexOf('} else {', interruptedAt);
  const branchEnd = mutantReceiver.indexOf('\n\t\t}', nonInterruptedAt);
  const readinessAt = mutantReceiver.indexOf('if ready == 0 {', branchAt);
  const receiveAt = mutantReceiver.indexOf('unix.Recvmsg(', readinessAt);
  assert(branchAt >= 0 && interruptedAt > branchAt && nonInterruptedAt > interruptedAt && branchEnd > nonInterruptedAt &&
    !mutantReceiver.slice(interruptedAt, nonInterruptedAt).includes('continue') &&
    !mutantReceiver.slice(interruptedAt, nonInterruptedAt).includes('return') &&
    mutantReceiver.slice(interruptedAt, nonInterruptedAt).includes('poll[0].Revents = unix.POLLIN') &&
    mutantReceiver.slice(interruptedAt, nonInterruptedAt).includes('ready = 1') &&
    mutantReceiver.slice(nonInterruptedAt, branchEnd).includes('return -1, 0, 0, errors.New(checkpointLocalObserverCustodyReceiverUnavailable)') &&
    readinessAt > branchAt && receiveAt > readinessAt,
  'custody fabricated-readiness mutant must set readiness and fall through the real readiness/Recvmsg path while preserving non-EINTR failure');
  assert.throws(() => assertPollInterruptRetrySource(receiverMutant), undefined, 'actual source predicate accepted custody fabricated-readiness mutant');
}

function replaceGoFunction(source, signature, before, after, label) {
  const start = source.indexOf(`\nfunc ${signature}`);
  const next = source.indexOf('\nfunc ', start + 1);
  assert(start >= 0, `${label}: Go function boundary is missing or ambiguous`);
  const end = next >= 0 ? next : source.length;
  const body = source.slice(start, end);
  const first = body.indexOf(before);
  assert(first >= 0 && body.indexOf(before, first + before.length) < 0, `${label} mutant anchor is not exact-once`);
  const changed = body.slice(0, first) + after + body.slice(first + before.length);
  return source.slice(0, start) + changed + source.slice(end);
}

function selfTestOuterFailureDiagnosticControls(kernel) {
  assertOuterFailureDiagnosticSource(kernel);
  const classSignature = 'checkpointLocalObserverParentFailureClass(capture *checkpointLocalObserverParentOutputCapture) string {';
  const headerSignature = 'checkpointLocalObserverParentFailureHeader(line string) bool {';
  const siteSignature = 'checkpointLocalObserverParentFailureSite(lineNumber int) string {';
  const controlsSignature = 'checkpointLocalObserverParentFailureClassifierControls(t *testing.T) {';
  const topSignature = 'TestCheckpointLocalObserverKernelFixture(t *testing.T) {';
  const mutations = [
    ['unbounded capture', kernel.replace('checkpointLocalObserverParentOutputLimit = 8 * 1024', 'checkpointLocalObserverParentOutputLimit = 8 * 1024 * 1024')],
    ['absent bounded capture', replaceGoFunction(kernel, 'checkpointLocalObserverKernelOuterParentDeath(t *testing.T) {', 'parent.Stdout, parent.Stderr = parentOutput, parentOutput', 'parent.Stdout, parent.Stderr = io.Discard, io.Discard', 'outer-parent bounded capture')],
    ['lost full-write count', kernel.replace('capture.overflow = true\n\t}\n\treturn len(p), nil', 'capture.overflow = true\n\t}\n\treturn 0, nil')],
    ['lost overflow tracking', kernel.replace('if writeCount != len(p) {\n\t\t\tcapture.overflow = true', 'if writeCount != len(p) {\n\t\t\t_ = writeCount')],
    ['raw output printing', replaceGoFunction(kernel, classSignature, 'return found', 'fmt.Printf("%s", data)\n\treturn found', 'bounded output classifier')],
    ['wrong source basename', replaceGoFunction(kernel, classSignature, 'const source = "checkpoint_local_observer_kernel_linux_test.go:"', 'const source = "unowned_test.go:"', 'bounded output classifier')],
    ['missing exact parent failure header', replaceGoFunction(kernel, classSignature, 'if failureHeader < 0 {', 'if false {', 'bounded output classifier')],
    ['duplicate failed header allowed', replaceGoFunction(kernel, classSignature, 'failureHeader >= 0 || !checkpointLocalObserverParentFailureHeader(line)', '!checkpointLocalObserverParentFailureHeader(line)', 'bounded output classifier')],
    ['unanchored source location allowed', replaceGoFunction(kernel, classSignature, 'if !strings.HasPrefix(line, prefix) {', 'if false {', 'bounded output classifier')],
    ['unknown assertion site allowed', replaceGoFunction(kernel, classSignature, 'site == "" || found != ""', 'found != ""', 'bounded output classifier')],
    ['duplicate source site allowed', replaceGoFunction(kernel, classSignature, 'site == "" || found != ""', 'site == ""', 'bounded output classifier')],
    ['wrong test owner accepted', replaceGoFunction(kernel, headerSignature, 'TestCheckpointLocalObserverKernelFixture', 'TestCheckpointLocalObserverKernelSentinel', 'exact failed-test header parser')],
    ['arbitrary line range allowed', replaceGoFunction(kernel, siteSignature, 'case 245,', 'case 1, 2, 3, 4, 5, 245,', 'parent failure site allowlist')],
    ['Go classifier test omitted', replaceGoFunction(kernel, topSignature, 'checkpointLocalObserverParentFailureClassifierControls(t)', '/* classifier table omitted */', 'inventoried kernel top fixture')],
    ['decisive classifier control omitted', replaceGoFunction(kernel, controlsSignature, 'name: "duplicate source sites"', 'name: "duplicate source sites omitted"', 'parent failure classifier Go controls')],
    ['missing failure diagnostic', kernel.replace('__CHECKPOINT_LOCAL_OBSERVER_PARENT_FAILURE__ reason=%s parent=%s status=%s', '__CHECKPOINT_LOCAL_OBSERVER_DIAGNOSTIC_REMOVED__ reason=%s parent=%s status=%s')],
    ['missing original pidfd status', kernel.replace('checkpointLocalObserverParentTerminalClass(parentPIDFD)', '"terminal"')],
    ['diagnostic success by itself', kernel.replace('if custodyErr != nil || coordinatorPID <= 1 || coordinatorStart == 0 {', 'if false && custodyErr != nil || coordinatorPID <= 1 || coordinatorStart == 0 {')],
    ['wait added to uncertain failure', kernel.replace('reason := checkpointLocalObserverCustodyFailureClass(custodyErr)', 'parent.Wait()\n\t\treason := checkpointLocalObserverCustodyFailureClass(custodyErr)')],
    ['merged truncation result', replaceGoFunction(kernel, 'checkpointLocalObserverReceiveCoordinatorCustody(file *os.File, nonce string, timeout time.Duration) (int, int, uint64, error) {', 'flags&unix.MSG_CTRUNC != 0', 'flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0', 'coordinator custody receiver')],
  ];
  for (const [label, mutant] of mutations) {
    assert(mutant !== kernel, `${label} mutant could not be constructed`);
    let rejected = false;
    try { assertOuterFailureDiagnosticSource(mutant); } catch { rejected = true; }
    assert(rejected, `outer failure diagnostic source predicate accepted ${label} mutant`);
  }
}

function assertKernelParentAliasCleanup(kernel, body = kernel.slice(
  kernel.indexOf('\nfunc checkpointLocalObserverKernelFixtureBody('),
  kernel.indexOf('\nfunc ', kernel.indexOf('\nfunc checkpointLocalObserverKernelFixtureBody(') + 1),
)) {
  const aliasStart = body.indexOf('\tparentAliasCleanupRequired = true');
  const aliasEnd = body.indexOf('\n\tworkerReaped = false', aliasStart);
  const aliasBlock = aliasStart < 0 || aliasEnd < 0 ? '' : body.slice(aliasStart, aliasEnd);
  const preflightAt = aliasBlock.indexOf('if _, err := os.Lstat(alias); !errors.Is(err, os.ErrNotExist)');
  const pathAt = aliasBlock.indexOf('alias := filepath.Join(root, aliasName)');
  const symlinkAt = aliasBlock.indexOf('os.Symlink(root, alias)');
  const pinAt = aliasBlock.indexOf('aliasStat, ok := aliasInfo.Sys().(*syscall.Stat_t)');
  const childAt = aliasBlock.indexOf('checkpointLocalObserverKernelRunClientMode(t, alias,');
  const removeAt = aliasBlock.indexOf('checkpointLocalObserverRemovePinnedParentAlias(root, rootStat, aliasStat)');
  const confirmedAt = aliasBlock.indexOf('parentAliasCleanupConfirmed = true', removeAt);
  const markerAt = aliasBlock.indexOf('__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_SUBSTITUTION_DENIED__');
  const cleanupGuardAt = body.indexOf('if parentAliasCleanupRequired && !parentAliasCleanupConfirmed');
  const finalAliasAbsenceAt = body.indexOf('if _, err := os.Lstat(filepath.Join(root, "parent-substitution")); !errors.Is(err, os.ErrNotExist)');
  const rootRemoveAt = body.indexOf('os.RemoveAll(root)');
  assert(pathAt >= 0 && preflightAt > pathAt && symlinkAt > preflightAt && pinAt > symlinkAt && childAt > pinAt && removeAt > childAt && confirmedAt > removeAt && markerAt > confirmedAt,
    'parent-symlink negative must be preflight-absent, rooted inside the fixture, pinned, exercised, rechecked/removed, and absence-confirmed before its event');
  assert(!aliasBlock.includes('os.Remove(alias)') && !aliasBlock.includes('defer os.Remove(alias)') && !aliasBlock.includes('root + ".parent-substitution"'),
    'parent-symlink cleanup must not use a sibling path or unchecked pathname removal');
  assert(cleanupGuardAt >= 0 && finalAliasAbsenceAt > cleanupGuardAt && rootRemoveAt > finalAliasAbsenceAt && body.includes('parentAliasCleanupRequired, parentAliasCleanupConfirmed := false, true'),
    'outer private-root cleanup must preserve uncertain parent-alias state rather than remove or report success');

  const helperStart = kernel.indexOf('\nfunc checkpointLocalObserverRemovePinnedParentAlias(');
  const helperEnd = kernel.indexOf('\nfunc ', helperStart + 1);
  const helper = helperStart < 0 || helperEnd < 0 ? '' : kernel.slice(helperStart, helperEnd);
  const parentPinAt = helper.indexOf('unix.Fstat(rootFD, &held)');
  const namedParentAt = helper.indexOf('os.Lstat(root)');
  const aliasPinAt = helper.indexOf('unix.Fstatat(rootFD, aliasName, &current, unix.AT_SYMLINK_NOFOLLOW)');
  const targetAt = helper.indexOf('unix.Readlinkat(rootFD, aliasName, target[:])');
  const unlinkAt = helper.indexOf('unix.Unlinkat(rootFD, aliasName, 0)');
  const relativeAbsenceAt = helper.indexOf('if err := unix.Fstatat(rootFD, aliasName, &after, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT)');
  const pathAbsenceAt = helper.indexOf('if _, err := os.Lstat(filepath.Join(root, aliasName)); !errors.Is(err, os.ErrNotExist)');
  assert(helperStart >= 0 && helperEnd > helperStart && helper.includes('unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)') &&
    parentPinAt >= 0 && namedParentAt > parentPinAt && helper.includes('held.Dev != uint64(rootPin.Dev)') && helper.includes('namedStat.Ino != rootPin.Ino') &&
    aliasPinAt > namedParentAt && helper.includes('current.Dev != uint64(aliasPin.Dev)') && helper.includes('current.Ino != aliasPin.Ino') &&
    helper.includes('current.Uid != aliasPin.Uid') && helper.includes('current.Gid != aliasPin.Gid') && helper.includes('current.Nlink != aliasPin.Nlink') &&
    helper.includes('current.Mode&syscall.S_IFMT != syscall.S_IFLNK') && targetAt > aliasPinAt && helper.includes('string(target[:n]) != root') &&
    unlinkAt > targetAt && (helper.match(/unix\.Unlinkat\(rootFD, aliasName, 0\)/g) ?? []).length === 1 &&
    relativeAbsenceAt > unlinkAt && pathAbsenceAt > relativeAbsenceAt && helper.includes('replacement will not be removed') &&
    helper.includes('errors.Join(result, unix.Close(rootFD))') && !helper.includes('os.Remove('),
  'alias cleanup must hold and recheck the exact parent/symlink target and owner/link identity, unlink once relative to the held root, confirm absence, and surface close uncertainty');
}

function selfTestKernelSearchRootFixtureControls(kernel) {
  assertKernelSearchRootFixtureContract(kernel);
  const mutant = kernel.replace('"public-key-read-positive"', '"client"');
  assert(mutant !== kernel, 'search-only fixture positive mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(mutant), undefined, 'fixture positive removed before permission negatives passed the same predicate');
  const parentMutant = kernel.replace('os.Symlink(root, alias)', 'os.Mkdir(alias, 0700)');
  assert(parentMutant !== kernel, 'trust-root parent-symlink mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(parentMutant), undefined, 'missing parent-substitution control passed the same predicate');
  const heldUnlink = 'unix.Unlinkat(rootFD, aliasName, 0)';
  assert(kernel.split(heldUnlink).length === 2, 'held-root alias unlink mutant anchor is not exact-once');
  const unpinnedPathRemoval = kernel.replace(heldUnlink, 'os.Remove(filepath.Join(root, aliasName))');
  assert(unpinnedPathRemoval !== kernel, 'unchecked pathname-removal mutant could not be constructed');
  assert.throws(() => assertKernelSearchRootFixtureContract(unpinnedPathRemoval), undefined,
    'unchecked pathname-only parent-alias removal passed the actual fixture source predicate');
  const siblingAlias = kernel.replace('alias := filepath.Join(root, aliasName)', 'alias := root + ".parent-substitution"');
  assert(siblingAlias !== kernel, 'sibling-alias mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(siblingAlias), undefined, 'sibling parent alias outside the private root passed the same predicate');
  const uncheckedReplacement = kernel.replace('current.Ino != aliasPin.Ino || ', '');
  assert(uncheckedReplacement !== kernel, 'symlink-inode recheck mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(uncheckedReplacement), undefined, 'replacement symlink without exact inode recheck passed the same predicate');
  const absentProofOmitted = kernel.replace('if _, err := os.Lstat(filepath.Join(root, aliasName)); !errors.Is(err, os.ErrNotExist) {', 'if false {');
  assert(absentProofOmitted !== kernel, 'alias-absence mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(absentProofOmitted), undefined, 'parent-alias cleanup without pathname absence confirmation passed the same predicate');
  const cleanupFenceOmitted = kernel.replace('if parentAliasCleanupRequired && !parentAliasCleanupConfirmed {', 'if false && parentAliasCleanupRequired && !parentAliasCleanupConfirmed {');
  assert(cleanupFenceOmitted !== kernel, 'outer cleanup-fence mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(cleanupFenceOmitted), undefined, 'outer cleanup without alias uncertainty fence passed the same predicate');
  const outerAbsenceOmitted = kernel.replace('if _, err := os.Lstat(filepath.Join(root, "parent-substitution")); !errors.Is(err, os.ErrNotExist) {', 'if false {');
  assert(outerAbsenceOmitted !== kernel, 'outer alias-absence mutant target is absent');
  assert.throws(() => assertKernelSearchRootFixtureContract(outerAbsenceOmitted), undefined, 'outer cleanup without a final alias absence check passed the same predicate');
}

function assertRegisteredSearchRootMutant(verifier) {
  const start = verifier.indexOf('\nfunction runKernelSearchRootO_RDONLYMutant(');
  const end = verifier.indexOf('\ntry {', start + 1);
  assert(start >= 0 && end > start, 'compiled O_RDONLY trust-root mutant registration boundary is missing or ambiguous');
  const body = verifier.slice(start, end);
  const positiveRun = body.indexOf('const positive = withLinuxBinary(');
  const knownPositive = body.indexOf("positive.split('__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__').length !== 2");
  const mutantRun = body.indexOf('const output = withLinuxBinary(');
  assert(verifier.includes("'--mode=kernel-opath-mutant'") && verifier.includes("mode === '--mode=kernel-opath-mutant'") && verifier.includes('runKernelSearchRootO_RDONLYMutant(contracts.sources)') &&
    positiveRun >= 0 && knownPositive > positiveRun && mutantRun > knownPositive &&
    body.includes("assertion: 'unprivileged public-key read did not preserve exact search-root and leaf pins'") &&
    (body.match(/cleanupMarker: '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__'/g) ?? []).length === 2,
  'compiled O_RDONLY mutant is not explicitly registered after a known positive with decisive rejection and cleanup proof');
}

function selfTestRegisteredSearchRootMutant(verifier) {
  assertRegisteredSearchRootMutant(verifier);
  const start = verifier.indexOf('\nfunction runKernelSearchRootO_RDONLYMutant(');
  const end = verifier.indexOf('\ntry {', start + 1);
  const body = verifier.slice(start, end);
  const noPositive = verifier.replace(body, body.replace('const positive = withLinuxBinary(', 'const mutantPositiveRemoved = withLinuxBinary('));
  assert.throws(() => assertRegisteredSearchRootMutant(noPositive), undefined, 'compiled O_RDONLY mutant without its baseline positive passed source controls');
  const noCleanup = verifier.replace(body, body.replaceAll("cleanupMarker: '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__',", ''));
  assert.throws(() => assertRegisteredSearchRootMutant(noCleanup), undefined, 'compiled O_RDONLY mutant without cleanup evidence passed source controls');
}

function buildWslArgv(programArgs) {
  return ['-d', 'Ubuntu', '-u', 'root', '--exec', ...programArgs];
}

function wsl(programArgs, options = {}, invoke = run) {
  return invoke('wsl.exe', buildWslArgv(programArgs), options);
}

function spawnWsl(programArgs, options = {}, invoke = spawnSync) {
  return invoke('wsl.exe', buildWslArgv(programArgs), options);
}

function wslPath(localPath, invokeWsl = wsl) {
  const result = invokeWsl(['wslpath', '-a', localPath]).trim();
  if (!result.startsWith('/') || /[\r\n]/.test(result)) throw new Error('path did not map to one canonical WSL absolute path');
  return result;
}

function shellQuote(value) { return `'${String(value).replaceAll("'", "'\\''")}'`; }

function buildLinuxTestCommand({ repo, bin, env, timeoutSeconds, runRegex }) {
  const selectedEnv = env.map(shellQuote).join(' ');
  return `cd -- ${shellQuote(repo)} && timeout --signal=TERM --kill-after=5s ${timeoutSeconds}s env -i PATH=/usr/bin:/bin HOME=/root LANG=C LC_ALL=C ${selectedEnv} ${shellQuote(bin)} -test.v -test.count=1 -test.timeout=${timeoutSeconds}s -test.run=${shellQuote(runRegex)}`;
}

function assertWslPathArgv(argv, localPath) {
  assert.deepEqual(argv, ['-d', 'Ubuntu', '-u', 'root', '--exec', 'wslpath', '-a', localPath]);
}

function assertQuotedLinuxCommand(command, repo, bin, rawWindowsPaths) {
  assert(command.includes(`cd -- ${shellQuote(repo)} &&`), 'Linux command does not separately shell-quote the converted repository path');
  assert(command.includes(` ${shellQuote(bin)} -test.v`), 'Linux command does not separately shell-quote the converted binary path');
  assert(rawWindowsPaths.every((value) => !command.includes(value)), 'raw Windows path was interpolated into the Bash command');
}

function selfTestWslArgvTransport(verifierSource) {
  const normalStart = verifierSource.indexOf('\nfunction wsl(');
  const pathStart = verifierSource.indexOf('\nfunction wslPath(', normalStart + 1);
  const quoteStart = verifierSource.indexOf('\nfunction shellQuote(', pathStart + 1);
  const spawnStart = verifierSource.indexOf('\nfunction spawnWsl(');
  const buildStart = verifierSource.indexOf('\nfunction buildLinuxTestCommand(', spawnStart + 1);
  const binaryStart = verifierSource.indexOf('\nfunction withLinuxBinary(');
  const authorityStart = verifierSource.indexOf('\nconst authorityTests =', binaryStart + 1);
  assert(normalStart >= 0 && pathStart > normalStart && quoteStart > pathStart &&
    verifierSource.slice(normalStart, pathStart).includes('buildWslArgv(programArgs)') &&
    verifierSource.slice(pathStart, quoteStart).includes("invokeWsl(['wslpath', '-a', localPath])"),
  'normal path helper bypassed exact argv builder or lost wslpath operands');
  assert(spawnStart >= 0 && buildStart > spawnStart && binaryStart > buildStart && authorityStart > binaryStart &&
    verifierSource.slice(binaryStart, authorityStart).includes("spawnWsl(['bash', '--noprofile', '--norc', '-lc', command], {"),
  'mutant direct spawn bypassed shared argv builder or fixed Bash shell');

  const cases = [
    {
      windows: String.raw`C:\Users\Sasha\Observer Projects\O'Brien\checkout`,
      mapped: "/mnt/c/Users/Sasha/Observer Projects/O'Brien/checkout",
    },
    {
      windows: String.raw`E:\Agent Temp\observer path\binary's folder\nodeagent-linux.test`,
      mapped: "/mnt/e/Agent Temp/observer path/binary's folder/nodeagent-linux.test",
    },
  ];
  const mappedPaths = [];
  for (const { windows, mapped } of cases) {
    let capturedProgram;
    let capturedArgv;
    const converted = wslPath(windows, (programArgs) => wsl(programArgs, {}, (program, argv) => {
      capturedProgram = program;
      capturedArgv = argv;
      return `${mapped}\n`;
    }));
    assert.equal(converted, mapped, 'injected path mapper must return one canonical absolute path');
    assert.equal(capturedProgram, 'wsl.exe');
    assertWslPathArgv(capturedArgv, windows);
    mappedPaths.push(mapped);

    const invalidPathVectors = [
      ['default-shell separator', ['-d', 'Ubuntu', '-u', 'root', '--', 'wslpath', '-a', windows]],
      ['missing -a option', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'wslpath', windows]],
      ['missing path operand', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'wslpath', '-a']],
      ['merged path operand', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'wslpath', `-a${windows}`]],
      ['raw path interpolation', ['-d', 'Ubuntu', '-u', 'root', '--exec', `wslpath -a ${windows}`]],
    ];
    for (const [label, vector] of invalidPathVectors) {
      assert.throws(() => assertWslPathArgv(vector, windows), undefined, `${label} must fail exact argv control`);
    }
  }

  const [repo, bin] = mappedPaths;
  const command = buildLinuxTestCommand({
    repo, bin, env: ['CHECKPOINT_LOCAL_OBSERVER_KERNEL=1'], timeoutSeconds: 45,
    runRegex: '^TestCheckpointLocalObserverKernelFixture$',
  });
  assertQuotedLinuxCommand(command, repo, bin, cases.map(({ windows }) => windows));
  assert(command.includes("'/mnt/c/Users/Sasha/Observer Projects/O'\\''Brien/checkout'"), 'Bash repo quoting failed for space/apostrophe path');
  const bashArgv = buildWslArgv(['bash', '--noprofile', '--norc', '-lc', command]);
  assert.deepEqual(bashArgv, ['-d', 'Ubuntu', '-u', 'root', '--exec', 'bash', '--noprofile', '--norc', '-lc', command]);
  let capturedMutantArgv;
  const fakeMutant = spawnWsl(['bash', '--noprofile', '--norc', '-lc', command], { timeout: 1000 }, (program, argv, options) => {
    assert.equal(program, 'wsl.exe');
    assert.deepEqual(options, { timeout: 1000 });
    capturedMutantArgv = argv;
    return { status: 0 };
  });
  assert.equal(fakeMutant.status, 0);
  assert.deepEqual(capturedMutantArgv, bashArgv, 'mutant execution must use identical exact direct argv and explicit Bash');
  assert.throws(() => assertQuotedLinuxCommand(command.replace(shellQuote(repo), repo), repo, bin, cases.map(({ windows }) => windows)), undefined,
    'unquoted command path must fail');
  assert.throws(() => assertQuotedLinuxCommand(command.replace(shellQuote(repo), cases[0].windows), repo, bin, cases.map(({ windows }) => windows)), undefined,
    'raw Windows interpolation must fail');
}

function withLinuxBinary({ tags = '', runRegex, env = [], timeoutSeconds = 70, mutant, mutantFailure, cleanupMarker }) {
  const prefix = path.join(os.tmpdir(), 'checkpoint-local-observer-verifier-');
  const temp = mkdtempSync(prefix);
  const before = lstatSync(temp);
  const binary = path.join(temp, 'nodeagent-linux.test');
  let cleanupConfirmed = false;
  try {
    const compile = ['test', '-c'];
    if (tags) compile.push('-tags', tags);
    if (mutant) {
      const sourcePath = path.join(root, mutant.file);
      const changedPath = path.join(temp, 'mutant.go');
      const overlayPath = path.join(temp, 'overlay.json');
      writeFileSync(changedPath, mutant.source, { flag: 'wx', mode: 0o600 });
      writeFileSync(overlayPath, JSON.stringify({ Replace: { [sourcePath]: changedPath } }), { flag: 'wx', mode: 0o600 });
      compile.push('-overlay', overlayPath);
    }
    compile.push('-o', binary, './internal/nodeagent');
    run('go', compile, { env: { ...process.env, GOOS: 'linux', GOARCH: 'amd64', CGO_ENABLED: '0', GOENV: 'off', GOFLAGS: '', GOTOOLCHAIN: 'local' }, timeout: 150_000 });
    const repo = wslPath(root);
    const bin = wslPath(binary);
    const command = buildLinuxTestCommand({ repo, bin, env, timeoutSeconds, runRegex });
    if (mutantFailure) {
      const result = spawnWsl(['bash', '--noprofile', '--norc', '-lc', command], {
        cwd: root, encoding: 'utf8', timeout: (timeoutSeconds + 20) * 1000, maxBuffer: 16 * 1024 * 1024,
      });
      if (result.error) throw result.error;
      const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
      const escaped = mutantFailure.testName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const runEvents = output.match(new RegExp(`^=== RUN\\s+${escaped}\\s*$`, 'gm')) ?? [];
      const failEvents = output.match(new RegExp(`^--- FAIL: ${escaped}(?:\\s|$)`, 'gm')) ?? [];
      const skipped = new RegExp(`^--- SKIP: ${escaped}(?:\\s|$)`, 'm').test(output);
      if (result.status === 0 || runEvents.length !== 1 || failEvents.length !== 1 || skipped || !output.includes(mutantFailure.assertion)) {
        throw new Error(`${mutant.label} did not reach its expected behavioral assertion failure (status=${result.status}): ${output.slice(-4000)}`);
      }
      if (cleanupMarker) {
        if (output.split(cleanupMarker).length !== 2) throw new Error(`${mutant.label} cleanup marker is absent or duplicated; preserving ${temp}`);
        cleanupConfirmed = true;
      }
      return output;
    }
    const output = wsl(['bash', '--noprofile', '--norc', '-lc', command], { timeout: (timeoutSeconds + 20) * 1000, maxBuffer: 16 * 1024 * 1024 });
    if (cleanupMarker) {
      if (output.split(cleanupMarker).length !== 2) throw new Error(`kernel fixture did not emit one independently confirmed cleanup marker; preserving ${temp}`);
      cleanupConfirmed = true;
    }
    return output;
  } finally {
    const current = lstatSync(temp);
    if (path.dirname(temp) !== os.tmpdir() || !path.basename(temp).startsWith(path.basename(prefix)) || !current.isDirectory() || current.dev !== before.dev || current.ino !== before.ino) {
      throw new Error(`private verifier directory identity changed; preserving ${temp}`);
    }
    if (!cleanupMarker || cleanupConfirmed) rmSync(temp, { recursive: true, force: true });
    else process.stderr.write(`kernel fixture cleanup is uncertain; preserving private verifier workspace ${temp}\n`);
  }
}

const authorityTests = [
  'TestCheckpointLocalObserverCanonicalRequest',
  ...['duplicate', 'unknown', 'case-variant', 'null', 'whitespace', 'trailing-value', 'short-nonce', 'unsupported-ver'].map((name) => `TestCheckpointLocalObserverCanonicalRequest/${name}`),
  'TestCheckpointLocalObserverSignedResponseBoundaries',
  'TestCheckpointLocalObserverIdentityAndBindingJoins',
  ...['caller-pid-namespace', 'worker-executable', 'worker-start', 'custody-digest', 'init-pid', 'init-not-root', 'worker-not-root', 'pid-1-worker', 'expired'].map((name) => `TestCheckpointLocalObserverIdentityAndBindingJoins/${name}`),
];
const linuxRegressionTests = [
  'TestCheckpointObserverRouteTmpfsCustodyControls',
  ...['noexec', 'readonly', 'missing-nosuid', 'missing-nodev', 'unbounded-size', 'malformed-size', 'missing-size', 'duplicate-size', 'unbounded-inodes', 'duplicate-inodes', 'conflicting-inode-modes', 'duplicate-inode64', 'duplicate-inode32', 'malformed-inode64', 'malformed-inode32', 'wrong-mode', 'nonroot-uid', 'nonroot-gid', 'duplicate-uid', 'conflicting-uid', 'wrong-filesystem', 'zero-mount-id', 'malformed-mount-id', 'wrong-target']
    .map((name) => `TestCheckpointObserverRouteTmpfsCustodyControls/${name}`),
  ...['not-attempted', 'not-mounted', 'attempt-latched', 'outstanding-references', 'wrong-proof-mount', 'wrong-mount-id', 'missing-children-clear', 'missing-underlying-custody', 'stale-parent', 'stale-mount-path']
    .map((name) => `TestCheckpointObserverRouteTmpfsCustodyControls/unmount-${name}`),
  'TestCheckpointLocalObserverPolicyCanonicalDecoder',
  ...['duplicate', 'unknown', 'case-variant', 'null', 'whitespace', 'trailing'].map((name) => `TestCheckpointLocalObserverPolicyCanonicalDecoder/${name}`),
  'TestCheckpointLocalObserverHeldFileIdentityComparison',
  ...['inode', 'owner', 'group', 'links', 'mode', 'size', 'mtime', 'ctime'].map((name) => `TestCheckpointLocalObserverHeldFileIdentityComparison/${name}`),
  'TestCheckpointLocalObserverPeerCredentialAdmission',
  ...['wrong-uid', 'wrong-gid'].map((name) => `TestCheckpointLocalObserverPeerCredentialAdmission/${name}`),
  'TestCheckpointLocalObserverIdentityMatchesCurrentness',
  ...['pid', 'uid', 'gid', 'start', 'namespace', 'executable-path', 'executable-digest', 'cgroup', 'boot'].map((name) => `TestCheckpointLocalObserverIdentityMatchesCurrentness/${name}`),
  'TestCheckpointLocalObserverFixtureWrongGIDIsDistinct',
  'TestCheckpointLocalObserverPlatformEntrypointHasFixedPaths',
];

function replaceUnique(source, before, after, label) {
  const first = source.indexOf(before);
  assert(first >= 0 && source.indexOf(before, first + before.length) < 0, `${label}: mutant target is not unique`);
  return source.slice(0, first) + after + source.slice(first + before.length);
}

function behavioralMutant({ sources, file, needle, replacement, label, testName, assertion }) {
  const source = sources.get(file);
  assert(source, `${label}: source is outside the owned frozen inventory`);
  const mutantSource = replaceUnique(source, needle, replacement, label);
  const output = withLinuxBinary({
    runRegex: `^${testName}$`, timeoutSeconds: 45,
    mutant: { file, source: mutantSource },
    mutantFailure: { label, testName, assertion },
  });
  assert(output.includes(`=== RUN   ${testName}`), `${label}: target behavioral test was not run`);
  assert(output.includes(assertion), `${label}: decisive failure assertion is absent`);
}

function runBehavioralMutants(sources) {
  behavioralMutant({
    sources, file: owned[0], label: 'signature-verification bypass',
    needle: 'return ed25519.Verify(public, signed, signature)', replacement: 'return true',
    testName: 'TestCheckpointLocalObserverSignedResponseBoundaries', assertion: 'wrong pinned root key was accepted',
  });
  behavioralMutant({
    sources, file: owned[1], label: 'SO_PEERCRED policy bypass',
    needle: 'return uid == policy.PeerUID && gid == policy.PeerGID', replacement: 'return true',
    testName: 'TestCheckpointLocalObserverPeerCredentialAdmission', assertion: 'mutated peer credentials were allowed',
  });
  behavioralMutant({
    sources, file: owned[1], label: 'used currentness comparison bypass',
    needle: 'return expected == current', replacement: 'return true',
    testName: 'TestCheckpointLocalObserverIdentityMatchesCurrentness', assertion: 'changed pid identity was accepted',
  });
}

function runKernelSearchRootO_RDONLYMutant(sources) {
  const file = owned[1];
  const source = sources.get(file);
  const open = 'unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW';
  assert(source.split(open).length - 1 === 2, 'search-only trust-root O_RDONLY mutant expected exactly two O_PATH directory opens');
  const mutantSource = source.replaceAll(open, 'unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW');
  const positive = withLinuxBinary({
    tags: 'checkpoint_local_observer_kernel', runRegex: '^TestCheckpointLocalObserverKernelFixture$',
    env: ['CHECKPOINT_LOCAL_OBSERVER_KERNEL=1'], timeoutSeconds: 190,
    cleanupMarker: '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__',
  });
  if (positive.split('__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__').length !== 2) {
    throw new Error('known positive did not prove public-key access through the search-only trust root');
  }
  const output = withLinuxBinary({
    tags: 'checkpoint_local_observer_kernel', runRegex: '^TestCheckpointLocalObserverKernelFixture$',
    env: ['CHECKPOINT_LOCAL_OBSERVER_KERNEL=1'], timeoutSeconds: 190,
    cleanupMarker: '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__',
    mutant: { file, source: mutantSource, label: 'search-only trust-root O_RDONLY mutant' },
    mutantFailure: { label: 'search-only trust-root O_RDONLY mutant', testName: 'TestCheckpointLocalObserverKernelFixture', assertion: 'unprivileged public-key read did not preserve exact search-root and leaf pins' },
  });
  if (output.split('__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__').length !== 2) {
    throw new Error('O_RDONLY trust-root mutant did not prove exact fixture cleanup after its expected positive failure');
  }
}

try {
  const contracts = sourceContracts();
  if (mode === '--mode=source-only') {
    selfTestSearchOnlyTrustRootControls(contracts.sources.get(owned[1]));
    selfTestKernelSearchRootFixtureControls(contracts.sources.get(owned[5]));
    selfTestOuterFailureDiagnosticControls(contracts.sources.get(owned[5]));
    selfTestPollInterruptRetryControls(contracts.sources.get(owned[5]));
    selfTestRegisteredSearchRootMutant(contracts.sources.get(owned[9]));
    selfTestParentDeathReportParser();
    selfTestParentDeathSourceControls(contracts.sources.get(owned[5]));
    selfTestWslArgvTransport(contracts.sources.get(owned[9]));
    console.log('checkpoint local observer source-only verification passed');
  } else if (mode === '--mode=authority') {
    const selected = [...authorityTests, ...linuxRegressionTests];
    const output = withLinuxBinary({ runRegex: `^(${selected.filter((name) => !name.includes('/')).join('|')})$`, timeoutSeconds: 90 });
    inventory(output, selected);
    console.log('checkpoint local observer authority verification passed');
  } else if (mode === '--mode=kernel') {
    const selected = ['TestCheckpointLocalObserverKernelFixture'];
    const output = withLinuxBinary({ tags: 'checkpoint_local_observer_kernel', runRegex: '^TestCheckpointLocalObserverKernelFixture$', env: ['CHECKPOINT_LOCAL_OBSERVER_KERNEL=1'], timeoutSeconds: 190, cleanupMarker: parentExitMarker });
    inventory(output, selected);
    for (const marker of [
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_IPC_POSITIVE__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_PEER_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_GID_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_KEY_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WRONG_NONCE_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_IDENTITY_SUBSTITUTION_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_NAMESPACE_SUBSTITUTION_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_EXIT_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_WORKER_REPLACED_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_KEY_SUBSTITUTION_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_SEARCH_ROOT_POSITIVE__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_ROOT_SEARCH_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_GROUP_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PUBLIC_KEY_WRONG_MODE_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_PARENT_SUBSTITUTION_DENIED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_BROKER_CAPABILITY_POSTURE__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_UNRELATED_SURVIVED__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_UNRELATED_SURVIVED_ALL__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_CLEANUP__',
      '__CHECKPOINT_LOCAL_OBSERVER_KERNEL_POSITIVE__',
      parentReportMarker,
      parentNonceMarker,
      parentCompletionMarker,
      parentExitMarker,
    ]) {
      if (output.split(marker).length !== 2) throw new Error(`kernel fixture marker is absent or duplicated: ${marker}`);
    }
    parseParentDeathReportOutput(output);
    console.log('checkpoint local observer kernel verification passed');
  } else if (mode === '--mode=kernel-opath-mutant') {
    runKernelSearchRootO_RDONLYMutant(contracts.sources);
    console.log('checkpoint local observer O_RDONLY trust-root mutant was rejected after the positive fixture setup');
  } else {
    const selected = [...authorityTests, ...linuxRegressionTests];
    const output = withLinuxBinary({ runRegex: `^(${selected.filter((name) => !name.includes('/')).join('|')})$`, timeoutSeconds: 90 });
    inventory(output, selected);
    runBehavioralMutants(contracts.sources);
    console.log('checkpoint local observer regression verification passed');
  }
} catch (error) {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
}
