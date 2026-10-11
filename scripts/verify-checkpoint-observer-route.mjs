#!/usr/bin/env node
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, unlinkSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const fixedGoBin = 'C:/Users/Sasha/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin';
const fixedGo = `${fixedGoBin}/go.exe`;
const fixedSSH = 'C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe';
const fixedIdentity = 'C:/Users/Sasha/.ssh/cmp170_proxmox';
const fixedKnownHosts = 'C:/Users/Sasha/.ssh/known_hosts';
const allowedModes = new Set(['--source', '--unit', '--kernel']);
const mode = process.argv[2];
if (process.argv.length !== 3 || !allowedModes.has(mode)) {
  console.error('usage: node scripts/verify-checkpoint-observer-route.mjs --source|--unit|--kernel');
  process.exit(2);
}

const owned = [
  'internal/checkpointgpuobserver/protocol.go',
  'internal/checkpointgpuobserver/protocol_test.go',
  'internal/checkpointgpuobserver/observer_linux.go',
  'internal/checkpointgpuobserver/observer_linux_test.go',
  'internal/checkpointgpuobserver/observer_kernel_linux_test.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_linux.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_other.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_test.go',
  'internal/nodeagent/checkpoint_host_gpu_bridge_linux_test.go',
  'internal/nodeagent/checkpoint_managed_binding_linux.go',
  'internal/nodeagent/checkpoint_managed_binding_linux_test.go',
  'scripts/verify-checkpoint-container-attribution.mjs',
  'scripts/verify-checkpoint-managed-binding.mjs',
  'internal/nodeagent/checkpoint_local_observer_linux.go',
  'internal/nodeagent/checkpoint_local_observer_linux_test.go',
  'scripts/verify-checkpoint-local-observer.mjs',
  'internal/nodeagent/checkpoint_local_observer_kernel_linux_test.go',
  'scripts/verify-checkpoint-observer-route.mjs',
];
const sources = new Map(owned.map((name) => [name, readFileSync(path.join(root, name), 'utf8')]));

function requireSource(condition, message) {
  if (!condition) throw new Error(`checkpoint observer route source contract failed: ${message}`);
}

function functionBody(source, name) {
  const start = source.indexOf(`\nfunc ${name}`);
  if (start < 0 || source.indexOf(`\nfunc ${name}`, start + 1) >= 0) throw new Error(`missing or duplicate Go function ${name}`);
  const end = source.indexOf('\nfunc ', start + 1);
  if (end < 0) throw new Error(`unterminated Go function ${name}`);
  return source.slice(start, end);
}

function topLevelGoFunctionCounts(source) {
  const counts = new Map();
  for (const match of source.matchAll(/^func ([A-Za-z_][A-Za-z0-9_]*)\s*\(/gm)) counts.set(match[1], (counts.get(match[1]) ?? 0) + 1);
  return counts;
}

function hasUniqueTopLevelGoFunctions(source) {
  return [...topLevelGoFunctionCounts(source).values()].every((count) => count === 1);
}

function fixedPrivateTmpfsBuilderAccepts(source) {
  let builder;
  let mount;
  try {
    builder = functionBody(source, 'checkpointObserverRouteTmpfsOptions() string {');
    mount = functionBody(source, 'checkpointObserverRouteMountPrivateExecutableBin(root, bin string, rootFD int, rootDev, rootInode uint64, binFD int, binDev, binInode uint64) (*checkpointObserverRouteTmpfsMount, error) {');
  } catch {
    return false;
  }
  const option = source.match(/^\s*checkpointObserverRouteTmpfsSize\s*=\s*"([^"]+)"\s*$/m)?.[1];
  return builder.includes('return checkpointObserverRouteTmpfsSize') &&
    option === 'size=128M,nr_inodes=128,mode=0711,uid=0,gid=0' &&
    mount.includes('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions())');
}

function replaceRegionOnce(text, startMarker, endMarker, before, after) {
  const start = text.indexOf(startMarker);
  const end = text.indexOf(endMarker, start);
  requireSource(start >= 0 && end > start, `mutant region ${startMarker} is not uniquely bounded`);
  const region = text.slice(start, end);
  requireSource(region.split(before).length === 2, `mutant anchor is not unique within ${startMarker}`);
  return text.slice(0, start) + region.replace(before, after) + text.slice(end);
}

function assertProtocol(protocol) {
  const validate = functionBody(protocol, 'ValidateResponse(response Response) error {');
  requireSource(validate.includes('response.Role != "node-agent" && response.Role != "fixed-supervisor" && response.Role != "local-observer"'),
    'response role enum is closed to exactly the existing two roles plus local-observer');
  requireSource(validate.includes('(response.Role == "fixed-supervisor" || response.Role == "local-observer") && response.PeerUID != 0'),
    'both root-only roles require UID zero');
  requireSource(!validate.includes('response.Role == "local-observer" && response.PeerUID == 0'),
    'local-observer role cannot be admitted with a nonroot UID');
}

function assertObserverPolicy(observer) {
  const config = functionBody(observer, 'validateObserverConfig(config ObserverConfig) error {');
  const authorize = functionBody(observer, 'authorizeObserverPeer(ctx context.Context, credentials *unix.Ucred, config ObserverConfig) (*heldProcess, PeerAuthority, ContainerAuthority, error) {');
  const authorizeUsing = functionBody(observer, 'authorizeObserverPeerUsing(ctx context.Context, credentials *unix.Ucred, config ObserverConfig,');
  const select = functionBody(observer, 'selectObserverPeerContainer(peer *heldProcess, authority PeerAuthority, containers []ContainerAuthority) (ContainerAuthority, error) {');
  const resolve = functionBody(observer, 'resolveContainerProcesses(ctx context.Context, request Request, authorities []ContainerAuthority, nodeContainer ContainerAuthority, role string) (ContainerAuthority, *heldProcess, *heldProcess, error) {');
  requireSource(config.includes('authority.Role != "node-agent" && authority.Role != "fixed-supervisor" && authority.Role != "local-observer"'),
    'host policy admits only the closed local-observer role extension');
  requireSource(config.includes('!roles["node-agent"] || !roles["fixed-supervisor"]'),
    'the two original roles remain required when local-observer is configured');
  requireSource(config.includes('authority.UID == 0 && authority.Role == "node-agent"') &&
    config.includes('(authority.Role == "fixed-supervisor" || authority.Role == "local-observer") && authority.UID != 0') && config.includes('roles[authority.Role]'),
    'legacy node-agent and root-only caller UID rules and role uniqueness are bounded in the implementation');
  requireSource(config.includes('peerAuthoritiesOverlap(local, supervisor)'),
    'overlapping root observer and supervisor authority is rejected at policy load');
  requireSource(authorize.includes('return authorizeObserverPeerUsing(ctx, credentials, config, openHeldProcess)') &&
    authorizeUsing.includes('matches++') && authorizeUsing.includes('if matches == 1') && authorizeUsing.includes('if matches > 1') &&
    authorizeUsing.includes('matches multiple fixed caller roles'), 'peer selection rejects multiple successful role matches instead of first-match authorization');
  requireSource(select.includes('case "local-observer":') && select.includes('eligible = eligible && authority.UID == 0'),
    'local-observer peer must join exactly one selected root container');
  requireSource(resolve.includes('(role == "node-agent" || role == "local-observer") && authority.CgroupRoot != nodeContainer.CgroupRoot'),
    'local-observer init/worker mapping is confined to the peer-selected container root');
}

function assertHostBridge(shared, linux, other) {
  const generic = functionBody(shared, 'observeCheckpointHostGPUAttribution(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {');
  const local = functionBody(shared, 'observeCheckpointHostGPUAttributionLocalObserver(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement) (checkpointHostGPUObservation, error) {');
  const fixed = functionBody(shared, 'observeCheckpointHostGPUAttributionForRole(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, role string) (checkpointHostGPUObservation, error) {');
  const responseRole = functionBody(shared, 'validateCheckpointHostGPUResponseRole(responseRole, expectedRole string) error {');
  const platform = functionBody(linux, 'observeCheckpointHostGPUAttributionPlatformForRole(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, expectedRole string) (checkpointHostGPUObservation, error) {');
  const platformUsing = functionBody(linux, 'observeCheckpointHostGPUAttributionPlatformForRoleUsing(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, expectedRole string, config checkpointHostGPUBridgeRuntimeConfig) (checkpointHostGPUObservation, error) {');
  requireSource(generic.includes('checkpointHostGPUExpectedRole(os.Geteuid())') && generic.includes('observeCheckpointHostGPUAttributionForRole'),
    'existing host caller routes retain fixed node-agent versus supervisor role selection');
  requireSource(local.includes('os.Geteuid() != 0') && local.includes('"local-observer"'),
    'dedicated local-observer bridge is fixed to the root collector');
  requireSource(fixed.includes('role != "node-agent" && role != "fixed-supervisor" && role != "local-observer"') &&
    fixed.includes('role == "local-observer" && os.Geteuid() != 0'), 'role choice is closed and cannot elevate a nonroot caller');
  requireSource(platform.includes('observeCheckpointHostGPUAttributionPlatformForRoleUsing') &&
    platformUsing.includes('verifyCheckpointHostGPUResponseForRole(responseBytes, publicKey, request, expectedRole') &&
    platformUsing.includes('recheckCheckpointHeldLocalProcess(worker)'),
    'the actual signed platform bridge checks exact expected role after the original signature/currentness joins');
  requireSource(responseRole.includes('responseRole != expectedRole') && other.includes('observeCheckpointHostGPUAttributionPlatformForRole') &&
    other.includes('unsupported on this platform'), 'wrong role and unsupported platform both fail closed');
}

function assertManagedRoute(managed, localObserver, managedTest) {
  const platform = functionBody(managed, 'observeCheckpointManagedBindingPlatform(ctx context.Context) (CheckpointManagedBinding, error) {');
  const route = functionBody(managed, 'routeCheckpointManagedBindingObserver(ctx context.Context, euid int, localObserver func(context.Context) (CheckpointManagedBinding, error), rootCollector func(context.Context) (CheckpointManagedBinding, error)) (CheckpointManagedBinding, error) {');
  const collector = functionBody(localObserver, 'checkpointLocalObserverCollect(ctx context.Context) (CheckpointManagedBinding, error) {');
  requireSource(platform.includes('routeCheckpointManagedBindingObserver(ctx, os.Geteuid()') &&
    platform.includes('ObserveCheckpointLocalAssociation(callCtx)') && platform.includes('observeCheckpointManagedBindingLinux(callCtx'),
    'production managed entry has explicit fixed local-client and original root-collector branches');
  requireSource(route.includes('if euid != 0') && route.includes('return CheckpointManagedBinding{}, err') &&
    route.includes('return binding, nil') && route.includes('return rootCollector(ctx)'),
    'nonroot client errors return zero binding without invoking root collector, while root retains direct collector');
  requireSource(collector.includes('nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver') &&
    !collector.includes('ObserveCheckpointManagedLocalBinding('), 'real root collector uses the explicit role-bound bridge and does not recurse publicly');
  requireSource(managedTest.includes('TestCheckpointManagedBindingObserverRoleRouting') &&
    managedTest.includes('rootCalls != 0') && managedTest.includes('got.CurrentIncarnation != ""') &&
    managedTest.includes('localCallsBeforeRoot := localCalls') && managedTest.includes('localCalls != localCallsBeforeRoot'),
    'actual managed route test checks local-only, root-only, and zero-binding-on-error behavior');
}

function assertSecurityJoins(protocol, observer, bridge, managed, localObserver) {
  const verify = functionBody(protocol, 'VerifyResponse(raw []byte, publicKey ed25519.PublicKey, expected Request, nowUnixNS int64) (Response, error) {');
  const policy = functionBody(observer, 'validateObserverConfig(config ObserverConfig) error {');
  const authorize = functionBody(observer, 'authorizeObserverPeer(ctx context.Context, credentials *unix.Ucred, config ObserverConfig) (*heldProcess, PeerAuthority, ContainerAuthority, error) {');
  const authorizeUsing = functionBody(observer, 'authorizeObserverPeerUsing(ctx context.Context, credentials *unix.Ucred, config ObserverConfig,');
  const selectContainer = functionBody(observer, 'selectObserverPeerContainer(peer *heldProcess, authority PeerAuthority, containers []ContainerAuthority) (ContainerAuthority, error) {');
  const observe = functionBody(observer, 'observeRequestUsing(ctx context.Context, request Request, peer *heldProcess, policy PeerAuthority, containers []ContainerAuthority, nodeContainer ContainerAuthority, inventory observerGPUInventorySource) (Response, error) {');
  const signedBridge = functionBody(bridge, 'observeCheckpointHostGPUAttributionPlatformForRoleUsing(ctx context.Context, workerPID int, expectedStart uint64, plan CheckpointLaunchPlan, placement CheckpointDevicePlacement, expectedRole string, config checkpointHostGPUBridgeRuntimeConfig) (checkpointHostGPUObservation, error) {');
  const signedResponse = functionBody(bridge, 'verifyCheckpointHostGPUResponseForRole(raw []byte, publicKey ed25519.PublicKey, request checkpointgpuobserver.Request, expectedRole string, nowUnixNS int64) (checkpointgpuobserver.Response, error) {');
  const route = functionBody(managed, 'routeCheckpointManagedBindingObserver(ctx context.Context, euid int, localObserver func(context.Context) (CheckpointManagedBinding, error), rootCollector func(context.Context) (CheckpointManagedBinding, error)) (CheckpointManagedBinding, error) {');
  const collector = functionBody(localObserver, 'checkpointLocalObserverCollect(ctx context.Context) (CheckpointManagedBinding, error) {');
  const localServer = functionBody(localObserver, 'checkpointLocalObserverServeConn(');
  requireSource(verify.includes('ed25519.Verify(publicKey, signed, signature)') && verify.includes('response.Worker.StartTicks != expected.WorkerStartTicks') &&
    verify.includes('response.Nonce != expected.Nonce') && verify.includes('response.ExpiresAtUnixNS <= nowUnixNS'),
    'signed response integrity and request/currentness validation remain in the verifier implementation');
  requireSource(policy.includes('!roles["node-agent"] || !roles["fixed-supervisor"]') && authorize.includes('return authorizeObserverPeerUsing(ctx, credentials, config, openHeldProcess)') && authorizeUsing.includes('matches++') && authorizeUsing.includes('if matches > 1 {'),
    'both legacy roles and unique caller UID/executable/cgroup/role joins remain enforced');
  requireSource(selectContainer.includes('authority.UID == 0') && selectContainer.includes('if matches != 1 {') && observe.includes('joinWorkerGPUProcess(rows, worker.value.PID, request.GPUUUID)') &&
    observe.includes('sameStableProcess(worker.value, workerAfter)') && observe.includes('device.PCI'),
    'root observer container selection, unique physical GPU join, and held worker currentness remain enforced');
  requireSource(signedBridge.includes('verifyCheckpointHostGPUResponseForRole(responseBytes, publicKey, request, expectedRole') &&
    signedResponse.includes('checkpointgpuobserver.VerifyResponse(raw, publicKey, request, nowUnixNS)') &&
    signedResponse.includes('validateCheckpointHostGPUResponseRole(response.Role, expectedRole)') &&
    signedBridge.includes('recheckCheckpointHeldLocalProcess(worker)'),
    'dedicated signed bridge retains signature, expected-role, and current-worker joins');
  requireSource(route.includes('if euid != 0 {') && route.includes('return CheckpointManagedBinding{}, err') && route.includes('return rootCollector(ctx)') &&
    collector.includes('nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver') && !collector.includes('ObserveCheckpointManagedLocalBinding('),
    'nonroot routing returns zero on local-client errors while the root collector uses the role-bound nonrecursive bridge');
  requireSource(localServer.includes('peerPID <= 1'), 'the production local observer retains the SO_PEERCRED child-PID guard');
}

function assertIntendedSourceMutants(protocol, observer, bridge, managed, localObserver) {
  const cases = [
    ['response signature verification removed', protocol, 'if !ed25519.Verify(publicKey, signed, signature) {', 'if false {', (v) => assertSecurityJoins(v, observer, bridge, managed, localObserver), 'signed response integrity and request/currentness validation remain in the verifier implementation'],
    ['caller role ambiguity accepted', observer, 'if matches > 1 {', 'if false {', (v) => assertSecurityJoins(protocol, v, bridge, managed, localObserver), 'both legacy roles and unique caller UID/executable/cgroup/role joins remain enforced'],
    ['node-agent UID-only authority admitted', observer, 'authority.UID == 0 && authority.Role == "node-agent"', 'false', (v) => assertObserverPolicy(v), 'legacy node-agent and root-only caller UID rules and role uniqueness are bounded in the implementation'],
    ['root supervisor/local role UID guard removed', observer, '(authority.Role == "fixed-supervisor" || authority.Role == "local-observer") && authority.UID != 0', 'false', (v) => assertObserverPolicy(v), 'legacy node-agent and root-only caller UID rules and role uniqueness are bounded in the implementation'],
    ['container uniqueness removed', observer, 'if matches != 1 {', 'if matches < 0 {', (v) => assertSecurityJoins(protocol, v, bridge, managed, localObserver), 'root observer container selection, unique physical GPU join, and held worker currentness remain enforced'],
    ['physical GPU UUID join removed', observer, 'joinWorkerGPUProcess(rows, worker.value.PID, request.GPUUUID)', 'joinWorkerGPUProcess(rows, worker.value.PID, "")', (v) => assertSecurityJoins(protocol, v, bridge, managed, localObserver), 'root observer container selection, unique physical GPU join, and held worker currentness remain enforced'],
    ['signed expected role check removed', bridge, 'validateCheckpointHostGPUResponseRole(response.Role, expectedRole)', 'validateCheckpointHostGPUResponseRole(expectedRole, expectedRole)', (v) => assertSecurityJoins(protocol, observer, v, managed, localObserver), 'dedicated signed bridge retains signature, expected-role, and current-worker joins'],
    ['held worker currentness removed', bridge, 'recheckCheckpointHeldLocalProcess(worker)', 'recheckCheckpointHeldLocalProcess(nil)', (v) => assertSecurityJoins(protocol, observer, v, managed, localObserver), 'dedicated signed bridge retains signature, expected-role, and current-worker joins'],
    ['nonroot direct fallback admitted', managed, 'if euid != 0 {', 'if false {', (v) => assertSecurityJoins(protocol, observer, bridge, v, localObserver), 'nonroot routing returns zero on local-client errors while the root collector uses the role-bound nonrecursive bridge'],
    ['collector generic wrapper restored', localObserver, 'nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver', 'nestedFootprint: observeNestedManagedCheckpointFootprint', (v) => assertSecurityJoins(protocol, observer, bridge, managed, v), 'nonroot routing returns zero on local-client errors while the root collector uses the role-bound nonrecursive bridge'],
  ];
  for (const [label, original, before, after, predicate, expectedFailure] of cases) {
    requireSource(original.split(before).length === 2, `${label} intended mutation anchor is not unique`);
    predicate(original);
    let failure;
    try { predicate(original.replace(before, after)); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${expectedFailure}`,
      `${label} mutant did not fail at its intended guard (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
  const serverStart = localObserver.indexOf('\nfunc checkpointLocalObserverServeConn(');
  const serverEnd = localObserver.indexOf('\nfunc ', serverStart + 1);
  requireSource(serverStart >= 0 && serverEnd > serverStart, 'local server implementation mutation region is missing');
  const serverBody = localObserver.slice(serverStart, serverEnd);
  requireSource(serverBody.split('peerPID <= 1').length === 2, 'SO_PEERCRED PID guard mutation anchor is not unique in its implementation function');
  const pidGuardMutant = localObserver.slice(0, serverStart) + serverBody.replace('peerPID <= 1', 'peerPID < 1') + localObserver.slice(serverEnd);
  let pidGuardFailure;
  try { assertSecurityJoins(protocol, observer, bridge, managed, localObserver); } catch (error) { pidGuardFailure = error; }
  requireSource(!pidGuardFailure, `SO_PEERCRED positive baseline failed: ${pidGuardFailure instanceof Error ? pidGuardFailure.message : ''}`);
  try { assertSecurityJoins(protocol, observer, bridge, managed, pidGuardMutant); } catch (error) { pidGuardFailure = error; }
  requireSource(pidGuardFailure instanceof Error && pidGuardFailure.message === 'checkpoint observer route source contract failed: the production local observer retains the SO_PEERCRED child-PID guard',
    `SO_PEERCRED child-PID mutant did not fail at its intended guard (${pidGuardFailure instanceof Error ? pidGuardFailure.message : 'accepted'})`);

  const collectorStart = localObserver.indexOf('\nfunc checkpointLocalObserverCollect(ctx context.Context) (CheckpointManagedBinding, error) {');
  const collectorEnd = localObserver.indexOf('\nfunc ', collectorStart + 1);
  requireSource(collectorStart >= 0 && collectorEnd > collectorStart, 'bounded public collector implementation region is missing');
  const collectorBody = localObserver.slice(collectorStart, collectorEnd);
  const recurseAnchor = 'return observeCheckpointManagedBindingLinux(ctx, checkpointManagedObservationSource{';
  requireSource(collectorBody.split(recurseAnchor).length === 2 && !collectorBody.includes('ObserveCheckpointManagedLocalBinding('),
    'public collector recursion positive has no exact single nonrecursive route');
  assertSecurityJoins(protocol, observer, bridge, managed, localObserver);
  const recursiveBody = collectorBody.replace(recurseAnchor,
    '_, _ = ObserveCheckpointManagedLocalBinding(ctx)\n\treturn observeCheckpointManagedBindingLinux(ctx, checkpointManagedObservationSource{');
  requireSource(recursiveBody !== collectorBody && recursiveBody.includes('_, _ = ObserveCheckpointManagedLocalBinding(ctx)'),
    'public-recursion mutant did not execute the public managed entrypoint inside the bounded collector body');
  const recursiveMutant = localObserver.slice(0, collectorStart) + recursiveBody + localObserver.slice(collectorEnd);
  let recursionFailure;
  try { assertSecurityJoins(protocol, observer, bridge, managed, recursiveMutant); } catch (error) { recursionFailure = error; }
  requireSource(recursionFailure instanceof Error && recursionFailure.message === 'checkpoint observer route source contract failed: nonroot routing returns zero on local-client errors while the root collector uses the role-bound nonrecursive bridge',
    `public collector recursion mutant missed its intended guard (${recursionFailure instanceof Error ? recursionFailure.message : 'accepted'})`);
}

function assertTaggedRuntimeImport(nodeKernel) {
  const predicate = 'tagged local observer fixture must import runtime for its existing KeepAlive and thread-pinning calls';
  const importLine = '\t"runtime"\n';
  const check = (source) => requireSource(source.includes(importLine) &&
    source.includes('runtime.KeepAlive(&value)') && source.includes('runtime.LockOSThread()') &&
    source.includes('runtime.UnlockOSThread()'), predicate);
  check(nodeKernel);
  requireSource(nodeKernel.split(importLine).length === 2, 'runtime import mutant anchor is not exact-once');
  const mutant = nodeKernel.replace(importLine, '');
  requireSource(mutant !== nodeKernel, 'runtime import mutant did not change source');
  let failure;
  try { check(mutant); } catch (error) { failure = error; }
  requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${predicate}`,
    `omitted runtime import mutant missed its intended source predicate (${failure instanceof Error ? failure.message : 'accepted'})`);
}

function assertComposedFixtureGroupAuthority(nodeKernel, localObserver, verifyMutants = true) {
  const routeStart = nodeKernel.indexOf('\nconst (\n\tcheckpointObserverRouteOptInEnv');
  const routeEnd = nodeKernel.indexOf('\nfunc checkpointLocalObserverKernelFixtureBody', routeStart);
  requireSource(routeStart >= 0 && routeEnd > routeStart, 'composed group fixture region is not uniquely bounded');
  const route = nodeKernel.slice(routeStart, routeEnd);
  const groupResolver = functionBody(nodeKernel, 'checkpointObserverRouteFixtureGroup() (*user.Group, uint32, error) {');
  const outer = functionBody(nodeKernel, 'TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {');
  const hostAuthority = functionBody(nodeKernel, 'checkpointObserverRouteWriteHostAuthority(configPath, keyPath, publicPath, socketPath string) ([]checkpointObserverRouteHeldPath, error) {');
  const exactCleanup = functionBody(nodeKernel, 'checkpointObserverRouteRemoveExactLocalTree(root string, rootDev, rootInode uint64, pins []checkpointObserverRouteHeldPath, mounted ...*checkpointObserverRouteMountedCleanup) error {');
  const treeControls = functionBody(nodeKernel, 'checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {');
  const client = functionBody(nodeKernel, 'TestCheckpointObserverRouteComposedClientChild(t *testing.T) {');
  const brokerConfig = functionBody(nodeKernel, 'checkpointObserverRouteComposedServerConfig(t *testing.T, workerPID int) checkpointLocalObserverRuntimeConfig {');
  const pid1 = functionBody(nodeKernel, 'checkpointObserverRouteComposedPID1(t *testing.T) {');
  const originalFixture = functionBody(nodeKernel, 'checkpointLocalObserverKernelFixtureBody(t *testing.T, abruptParent bool) {');
  const productionConfig = functionBody(localObserver, 'checkpointLocalObserverProductionConfig() checkpointLocalObserverRuntimeConfig {');
  const composedSites = [outer, hostAuthority, exactCleanup, treeControls, client, brokerConfig, pid1];
  const failure = 'composed fixture group must be the fixed pre-existing daemon identity with exact numeric GID 1 across every parent/host/cleanup/broker/client/PID1 boundary, while production and original fixture retain vram-governor';
  requireSource(route.includes('checkpointObserverRouteFixtureGroupName = "daemon"') &&
    route.includes('checkpointObserverRouteFixtureGroupID = 1') &&
    groupResolver.includes('user.LookupGroup(checkpointObserverRouteFixtureGroupName)') &&
    groupResolver.includes('group.Name != checkpointObserverRouteFixtureGroupName') &&
    groupResolver.includes('group.Gid != "1"') &&
    groupResolver.includes('groupID != checkpointObserverRouteFixtureGroupID') &&
    groupResolver.includes('strconv.ParseUint(group.Gid, 10, 32)') &&
    !groupResolver.includes('os.Getenv') && !groupResolver.includes('user.Current') &&
    route.split('user.LookupGroup(').length === 2 && !route.includes('user.LookupGroup("vram-governor")') &&
    composedSites.every((site) => site.includes('checkpointObserverRouteFixtureGroup()')) &&
    client.includes('nodeGroup: group.Name') && brokerConfig.includes('nodeGroup: group.Name') &&
    pid1.includes('PeerUID: 65534, PeerGID: groupID') &&
    originalFixture.includes('user.LookupGroup("vram-governor")') &&
    productionConfig.includes('nodeGroup:   "vram-governor"') &&
    !originalFixture.includes('checkpointObserverRouteFixtureGroup()') && !productionConfig.includes('checkpointObserverRouteFixtureGroup'),
    failure);
  if (!verifyMutants) return;
  const mutants = [
    ['exact name check omitted', replaceRegionOnce(nodeKernel, '\nfunc checkpointObserverRouteFixtureGroup()', '\nfunc TestCheckpointObserverRouteComposedKernelFixture', 'group.Name != checkpointObserverRouteFixtureGroupName', 'false') , localObserver],
    ['exact numeric GID check omitted', replaceRegionOnce(nodeKernel, '\nfunc checkpointObserverRouteFixtureGroup()', '\nfunc TestCheckpointObserverRouteComposedKernelFixture', 'group.Gid != "1"', 'false'), localObserver],
    ['caller-selected group admitted', replaceRegionOnce(nodeKernel, '\nfunc checkpointObserverRouteFixtureGroup()', '\nfunc TestCheckpointObserverRouteComposedKernelFixture', 'user.LookupGroup(checkpointObserverRouteFixtureGroupName)', 'user.LookupGroup(os.Getenv("GROUP"))'), localObserver],
    ['composed client group substituted partially', replaceRegionOnce(nodeKernel, '\nfunc TestCheckpointObserverRouteComposedClientChild(t *testing.T) {', '\nfunc TestCheckpointObserverRouteWorkerChild', 'checkpointObserverRouteFixtureGroup()', 'user.LookupGroup("vram-governor")'), localObserver],
    ['production group substituted with fixture identity', nodeKernel, localObserver.replace('nodeGroup:   "vram-governor"', 'nodeGroup:   checkpointObserverRouteFixtureGroupName')],
    ['original fixture substituted with composed identity', replaceRegionOnce(nodeKernel, '\nfunc checkpointLocalObserverKernelFixtureBody(', '\nfunc checkpointLocalObserverRemovePinnedParentAlias(', 'user.LookupGroup("vram-governor")', 'checkpointObserverRouteFixtureGroup()'), localObserver],
  ];
  for (const [label, mutantNode, mutantLocal] of mutants) {
    requireSource(mutantNode !== nodeKernel || mutantLocal !== localObserver, `${label} control mutant did not alter its exact source anchor`);
    let rejected;
    try { assertComposedFixtureGroupAuthority(mutantNode, mutantLocal, false); } catch (error) { rejected = error; }
    requireSource(rejected instanceof Error && rejected.message === `checkpoint observer route source contract failed: ${failure}`,
      `${label} mutant did not fail the intended fixed-group/source-boundary predicate`);
  }
}

function assertComposedRootPathAdmission(nodeKernel, verifyMutants = true) {
  const helperStart = '\nfunc checkpointObserverRoutePathAllowed(key, value, root, localRoot string) bool {';
  const controlsStart = '\nfunc checkpointObserverRoutePathAdmissionControls(t *testing.T) {';
  const controlsEnd = '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {';
  const predicate = 'composed root environment admits only the exact held outer root while retaining bounded host descendants and explicit local-root routing';
  const check = (source) => {
    const helper = functionBody(source, 'checkpointObserverRoutePathAllowed(key, value, root, localRoot string) bool {');
    const controls = functionBody(source, 'checkpointObserverRoutePathAdmissionControls(t *testing.T) {');
    const outer = functionBody(source, 'TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {');
    requireSource(helper.includes('if value == "" || filepath.Clean(value) != value') &&
      helper.includes('if key == checkpointObserverRouteRootEnv { return value == root }') &&
      helper.includes('return strings.HasPrefix(value, root+string(os.PathSeparator))') &&
      helper.includes('return value == localRoot || strings.HasPrefix(value, localRoot+string(os.PathSeparator))') &&
      !helper.includes('os.Getenv') && !helper.includes('strings.HasPrefix(value, root) { return true }') &&
      outer.includes('if !checkpointObserverRoutePathAllowed(key, value, root, localRoot) {') &&
      outer.split('checkpointObserverRoutePathAdmissionControls(t)').length === 2 &&
      outer.indexOf('checkpointObserverRoutePathAdmissionControls(t)') < outer.indexOf('checkpointObserverRouteRequireInitialHostNamespace()') &&
      controls.includes('"exact outer root"') && controls.includes('"host descendant"') &&
      controls.includes('"local root"') && controls.includes('"local descendant"') &&
      controls.includes('"wrong outer root value"') && controls.includes('"prefix-only outer root"') &&
      controls.includes('"outside path"') && controls.includes('"other key exact root"') &&
      controls.indexOf('"exact outer root"') < controls.indexOf('"wrong outer root value"') &&
      controls.indexOf('"local descendant"') < controls.indexOf('"outside path"'), predicate);
  };
  check(nodeKernel);
  if (!verifyMutants) return;
  const mutants = [
    ['exact root exception omitted', replaceRegionOnce(nodeKernel, helperStart, controlsStart, 'if key == checkpointObserverRouteRootEnv { return value == root }', 'if false { return false }')],
    ['exact root exception broadened to prefix', replaceRegionOnce(nodeKernel, helperStart, controlsStart, 'if key == checkpointObserverRouteRootEnv { return value == root }', 'if key == checkpointObserverRouteRootEnv { return strings.HasPrefix(value, root) }')],
    ['exact root exception admitted for another key', replaceRegionOnce(nodeKernel, helperStart, controlsStart, 'if key == checkpointObserverRouteRootEnv { return value == root }', 'if value == root { return true }')],
    ['path controls omitted from actual caller', replaceRegionOnce(nodeKernel, '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {', '\nfunc checkpointObserverRouteHoldRunParent()', 'checkpointObserverRoutePathAdmissionControls(t)', '/* path controls omitted */')],
    ['actual environment loop bypasses predicate', replaceRegionOnce(nodeKernel, '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {', '\nfunc checkpointObserverRouteHoldRunParent()', 'if !checkpointObserverRoutePathAllowed(key, value, root, localRoot) {', 'if false {')],
  ];
  for (const [label, mutant] of mutants) {
    requireSource(mutant !== nodeKernel, `${label} mutant did not alter its exact source anchor`);
    let rejected;
    try { check(mutant); } catch (error) { rejected = error; }
    requireSource(rejected instanceof Error && rejected.message === `checkpoint observer route source contract failed: ${predicate}`,
      `${label} mutant missed its intended exact-root admission predicate`);
  }
}

function assertComposedClientPinHandoff(nodeKernel, verifyMutants = true) {
  const heldStart = '\nfunc checkpointObserverRoutePublishClientBinaryHeld(source, destination string, destinationGID uint32)';
  const matchStart = '\nfunc checkpointObserverRouteClientPinMatches(pin checkpointObserverRouteHeldPath, path string, held syscall.Stat_t) bool {';
  const usingStart = '\nfunc checkpointObserverRoutePublishClientBinaryUsing(source, destination string, destinationGID uint32,';
  const predicate = 'published client custody must adopt a same-name O_PATH regular-file pin with full final-stat equality before writer settlement, and propagate every failure before client start';
  const metadata = ['pin.path == path', 'pin.fd >= 0', '!pin.isDir', 'pin.dev == uint64(held.Dev)', 'pin.inode == held.Ino', 'pin.uid == held.Uid', 'pin.gid == held.Gid', 'pin.mode == uint32(held.Mode)', 'pin.nlink == uint64(held.Nlink)', 'pin.size == held.Size'];
  const check = (source) => {
    const held = functionBody(source, 'checkpointObserverRoutePublishClientBinaryHeld(source, destination string, destinationGID uint32) (string, checkpointObserverRouteHeldPath, error) {');
    const match = functionBody(source, 'checkpointObserverRouteClientPinMatches(pin checkpointObserverRouteHeldPath, path string, held syscall.Stat_t) bool {');
    const using = functionBody(source, 'checkpointObserverRoutePublishClientBinaryUsing(source, destination string, destinationGID uint32,');
    const capture = functionBody(source, 'checkpointObserverRouteCaptureHeldPath(name string) (pin checkpointObserverRouteHeldPath, result error) {');
    const pid1 = functionBody(source, 'checkpointObserverRouteComposedPID1(t *testing.T) {');
    const callbackCapture = held.indexOf('checkpointObserverRouteCaptureHeldPath(destination)');
    const callbackCompare = held.indexOf('checkpointObserverRouteClientPinMatches(candidate, destination, held)');
    const callbackAdopt = held.indexOf('pin = candidate');
    const writerClose = 'defer func() { owned := destinationFD; destinationFD = -1; result = errors.Join(result, unix.Close(owned)) }()';
    const publicationCallback = using.indexOf('if err := holdCreated(destinationFD, finalDestination); err != nil');
    const publishReturn = using.lastIndexOf('return hex.EncodeToString(publishedDigest[:]), nil');
    const heldFailureBranch = 'if err != nil { return "", checkpointObserverRouteHeldPath{}, errors.Join(err, checkpointObserverRouteCloseHeldPath(&pin)) }';
    const callerPublish = pid1.indexOf('if err == nil { clientDigest, clientPin, err = checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID) }');
    const callerFailure = pid1.indexOf('t.Fatalf("publish exact held client test executable for unprivileged traversal: %v", err)');
    const callerAdopt = pid1.indexOf('localPins = append(localPins, clientPin)');
    const clientStart = pid1.indexOf('client.Start()');
    const callerFailureBranch = 'if err != nil {\n\t\tt.Fatalf("publish exact held client test executable for unprivileged traversal: %v", err)\n\t}';
    requireSource(callbackCapture >= 0 && callbackCapture < callbackCompare && callbackCompare < callbackAdopt &&
      held.includes('if err != nil { return err }') && held.includes('errors.Join(errors.New("published client O_PATH pin differs from final writer identity"), checkpointObserverRouteCloseHeldPath(&candidate))') &&
      held.split('checkpointObserverRouteCloseHeldPath(&candidate)').length === 2 && held.includes('pin := checkpointObserverRouteHeldPath{fd: -1}') &&
      held.includes(heldFailureBranch) && !held.includes('F_DUPFD') && !held.includes('FcntlInt') &&
      metadata.every((field) => match.includes(field)) &&
      capture.includes('unix.Open(name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)') && capture.includes('info.Mode()&os.ModeSymlink != 0') &&
      using.includes('unix.Open(destination, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)') &&
      using.includes(writerClose) && using.indexOf(writerClose) < publicationCallback && publicationCallback >= 0 && publicationCallback < publishReturn &&
      !using.includes('unix.Close(destinationFD)') &&
      using.includes('if err := holdCreated(destinationFD, finalDestination); err != nil { return "", errors.Join(errors.New("original published client custody could not be adopted by tree owner"), err) }') &&
      using.includes('!bytes.Equal(publishedBytes, contents) || publishedDigest != digest') &&
      using.includes('finalDestination.Dev != heldDestination.Dev') && using.includes('finalDestination.Mode&0777 != 0555') &&
      callerPublish >= 0 && callerPublish < callerFailure && callerFailure < callerAdopt && callerAdopt < clientStart && pid1.includes(callerFailureBranch) &&
      pid1.includes('localPins = append(localPins, clientPin)') && pid1.includes('clientPin.fd = -1'), predicate);

    const stat = { Dev: 11, Ino: 22, Uid: 0, Gid: 1, Mode: 0o100555, Nlink: 1, Size: 4096 };
    const pin = { path: '/private/bin/nodeagent.test', fd: 7, isDir: false, dev: 11, inode: 22, uid: 0, gid: 1, mode: 0o100555, nlink: 1, size: 4096 };
    const samePin = (p, s) => p.path === '/private/bin/nodeagent.test' && p.fd >= 0 && !p.isDir && p.dev === s.Dev && p.inode === s.Ino && p.uid === s.Uid && p.gid === s.Gid && p.mode === s.Mode && p.nlink === s.Nlink && p.size === s.Size;
    requireSource(samePin(pin, stat) && metadata.every((field) => { const key = field.startsWith('pin.') ? field.slice(4).split(' ')[0] : 'isDir'; const changed = { ...pin, [key]: key === 'isDir' ? true : key === 'fd' ? -1 : (typeof pin[key] === 'number' ? pin[key] + 1 : '/other') }; return !samePin(changed, stat); }),
      'pure client pin metadata controls must establish a known positive and reject each changed identity field');
  };
  check(nodeKernel);
  if (!verifyMutants) return;
  const mutants = [
    ['writable F_DUPFD custody retained', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'candidate, err := checkpointObserverRouteCaptureHeldPath(destination);', 'candidate, err := checkpointObserverRouteCaptureHeldPath(destination); _, _ = unix.FcntlInt(uintptr(1), unix.F_DUPFD_CLOEXEC, 0);')],
    ['capture omitted', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'candidate, err := checkpointObserverRouteCaptureHeldPath(destination); if err != nil { return err }', 'candidate := checkpointObserverRouteHeldPath{fd: -1}; var err error')],
    ['wrong capture path used', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'checkpointObserverRouteCaptureHeldPath(destination)', 'checkpointObserverRouteCaptureHeldPath(source)')],
    ['writer closed before O_PATH capture', replaceRegionOnce(nodeKernel, usingStart, '\nfunc checkpointObserverRouteRequireExactNames(', 'if holdCreated != nil {', 'if err := unix.Close(destinationFD); err != nil { return "", err }; if holdCreated != nil {')],
    ['capture error ignored', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'if err != nil { return err }', 'if false { return err }')],
    ['unadopted mismatch pin leaked', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'checkpointObserverRouteCloseHeldPath(&candidate)', 'nil')],
    ['writer-close result ignored', replaceRegionOnce(nodeKernel, heldStart, matchStart, 'if err != nil { return "", checkpointObserverRouteHeldPath{}, errors.Join(err, checkpointObserverRouteCloseHeldPath(&pin)) }', 'if false { return "", checkpointObserverRouteHeldPath{}, errors.Join(err, checkpointObserverRouteCloseHeldPath(&pin)) }')],
    ['publisher callback error ignored', replaceRegionOnce(nodeKernel, usingStart, '\nfunc checkpointObserverRouteRequireExactNames(', 'if err := holdCreated(destinationFD, finalDestination); err != nil', 'if err := holdCreated(destinationFD, finalDestination); false')],
    ['client start allowed after failed handoff', replaceRegionOnce(nodeKernel, '\nfunc checkpointObserverRouteComposedPID1(t *testing.T) {', '\nfunc checkpointObserverRouteWaitForSocket(', 'if err != nil {\n\t\tt.Fatalf("publish exact held client test executable for unprivileged traversal: %v", err)\n\t}', 'if false {\n\t\tt.Fatalf("publish exact held client test executable for unprivileged traversal: %v", err)\n\t}')],
    ...metadata.slice(3).map((field) => [`${field} comparison omitted`, replaceRegionOnce(nodeKernel, matchStart, usingStart, field, 'true')]),
    ['client pin descriptor omitted', replaceRegionOnce(nodeKernel, matchStart, usingStart, 'pin.fd >= 0', 'true')],
    ['client pin path identity omitted', replaceRegionOnce(nodeKernel, matchStart, usingStart, 'pin.path == path', 'true')],
    ['regular-file type omitted', replaceRegionOnce(nodeKernel, matchStart, usingStart, '!pin.isDir', 'true')],
  ];
  for (const [label, mutant] of mutants) {
    requireSource(mutant !== nodeKernel, `${label} mutant did not alter its exact source anchor`);
    let rejected;
    try { check(mutant); } catch (error) { rejected = error; }
    requireSource(rejected instanceof Error && rejected.message === `checkpoint observer route source contract failed: ${predicate}`,
      `${label} mutant missed its intended nonwritable creation-custody predicate`);
  }
}

function assertNestedFailureDiagnostic(nodeKernel, verifyMutants = true) {
  const predicate = 'nested failure reducer must validate one complete bounded assertion window, ambiguity, and actual zero-effect Go controls before private fixture work';
  const check = (source) => {
    const outer = functionBody(source, 'TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {');
    const diagnostic = functionBody(source, 'checkpointObserverRouteNestedFailureDiagnostic(err error, output *checkpointLocalObserverLimitedBuffer) string {');
    const reducer = functionBody(source, 'checkpointObserverRouteNestedAssertionSites(raw []byte) string {');
    const controls = functionBody(source, 'checkpointObserverRouteNestedFailureReducerControls() error {');
    const importBlock = source.slice(source.indexOf('import ('), source.indexOf('\n)', source.indexOf('import (')));
    const pid1 = functionBody(source, 'checkpointObserverRouteComposedPID1(t *testing.T) {');
    const guard = 'errors.Join(checkpointObserverRouteRequireInitialHostNamespace(), checkpointObserverRouteNestedFailureReducerControls())';
    requireSource(outer.includes(guard) && outer.indexOf(guard) < outer.indexOf('checkpointObserverRouteHoldRunParent()') &&
      outer.indexOf(guard) < outer.indexOf('os.CreateTemp("/run"') && outer.includes('if err != nil {') && outer.includes('checkpointObserverRouteNestedFailureDiagnostic(err, nestedOutput)') &&
      !pid1.includes('\n\tt.Helper()\n') && pid1.includes('failRawLocalRoot := func(cause error) { t.Helper(); t.Fatalf(') &&
      diagnostic.includes('output.snapshot()') && diagnostic.includes('errors.As(err, &child)') &&
      diagnostic.includes('child.Sys().(syscall.WaitStatus)') && diagnostic.includes('status.ExitStatus() <= 255') &&
      diagnostic.includes('status.Signal() <= 64') && diagnostic.includes('checkpointObserverRouteNestedAssertionSites(data)') && diagnostic.includes('overflowText') &&
      importBlock.includes('"regexp"') && reducer.includes('regexp.MustCompile(`^client=') &&
      reducer.includes('if len(raw) > 4096') && reducer.includes('const headerPrefix = "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture ("') &&
      reducer.includes('strings.HasPrefix(line, headerPrefix)') && reducer.includes('strings.HasPrefix(line, "--- FAIL")') &&
      reducer.includes('const run = "=== RUN   TestCheckpointObserverRouteComposedKernelFixture"') && reducer.includes('strings.HasPrefix(line, "=== RUN")') &&
      reducer.includes('const source = "    checkpoint_local_observer_kernel_linux_test.go:"') &&
      reducer.includes('strings.Contains(line, "checkpoint_local_observer_kernel_linux_test.go:")') &&
      reducer.includes('headers != 1 || invalid') && reducer.includes('strings.HasPrefix(line, "--- ")') && reducer.includes('line == "FAIL"') &&
      reducer.includes('closeSummary := func() { collecting = false; closed = true }') && reducer.includes('!collecting || closed') &&
      reducer.includes('strings.Index(record, ": ")') && reducer.includes('number > 4800') && reducer.includes('seen[number] || len(sites) == 4') && reducer.includes('sawAssertion') &&
      reducer.includes('const continuation = "            checkpoint_local_observer_kernel_linux_test.go:"') &&
      reducer.includes('continuationCandidate') && reducer.includes('continuationRequired') &&
      reducer.includes('continuationCandidate && !strings.HasPrefix(line, continuation)') &&
      reducer.includes('continuationMatch[1] != ownedClient') && reducer.includes('number == 1346 && !continuationLine') &&
      reducer.includes('if number == 1988') && reducer.includes('ownedClient = markerMatch[1]') &&
      reducer.includes('markerMatch[1] == "unavailable" && markerMatch[2] != "unavailable"') &&
      reducer.includes('passStage != 0') && reducer.includes('passStage != 1') && reducer.includes('passStage == 1') &&
      reducer.includes('if runCount != 1 || passStage != 0 || sawAssertion || closed') &&
      reducer.includes('line == "CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY"') &&
      reducer.includes('for _, line := range strings.Split(string(raw), "\\n")') && !reducer.includes('break') &&
      controls.includes('checkpointObserverRouteNestedAssertionSites([]byte(test.raw))') &&
      controls.includes('actual twelve-space continuation then cleanup site') && controls.includes('actual cleanup sentinel order positive') &&
      controls.includes('unavailable client without continuation') && controls.includes('unavailable client with continuation') &&
      controls.includes('finite continuation four-space') && controls.includes('finite continuation eight-space') &&
      controls.includes('finite continuation blank gap') && controls.includes('finite continuation foreign gap') &&
      controls.includes('finite continuation wrong client') && controls.includes('unavailable continuation wrong client') &&
      controls.includes('unavailable client forged broker') && controls.includes('stray twelve-space continuation') &&
      controls.indexOf('actual twelve-space continuation then cleanup site') < controls.indexOf('finite continuation four-space') &&
      controls.includes('legacy positive without RUN') && controls.includes('legacy positive with RUN') &&
      controls.includes('wrong run') && controls.includes('duplicate run') && controls.includes('overflow') &&
      controls.includes('summary closes permanently') && controls.includes('summary then assertion') && controls.includes('duplicate site') &&
      controls.includes('excess sites') &&
      controls.includes('cleanup sentinels reversed') && controls.includes('duplicate cleanup sentinel') &&
      controls.includes('impossible composed success sentinel') && controls.includes('impossible outside sentinel') &&
      controls.includes('stack only') && controls.includes('headerless') && controls.includes('incomplete') &&
      controls.includes('return fmt.Errorf("nested reducer control %s", test.name)') &&
      diagnostic.includes('checkpointObserverRouteNestedDiagnosticRecord(exit, overflowText, assertions, client, broker, phase)') &&
      diagnostic.includes('checkpointObserverRouteNestedStageRecords(data, overflow, assertions)') &&
      pid1.includes('clientRecord, brokerRecord, phaseSuffix, clientSource := checkpointObserverRoutePID1FailureRecord') &&
      pid1.includes('REMOTE_OBSERVER_ROUTE_PID1 client=%s broker=%s%s%s'), predicate);
  };
  check(nodeKernel);
  if (!verifyMutants) return;
  const outerStart = '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {';
  const outerEnd = '\nfunc checkpointObserverRouteHoldRunParent()';
  const reducerStart = '\nfunc checkpointObserverRouteNestedAssertionSites(raw []byte) string {';
  const reducerEnd = '\nfunc checkpointObserverRouteNestedFailureDiagnostic(';
  const diagnosticStart = '\nfunc checkpointObserverRouteNestedFailureDiagnostic(err error, output *checkpointLocalObserverLimitedBuffer) string {';
  const controlsStart = '\nfunc checkpointObserverRouteNestedFailureReducerControls() error {';
  const pid1Start = '\nfunc checkpointObserverRouteComposedPID1(t *testing.T) {';
  const waitSocketStart = '\nfunc checkpointObserverRouteWaitForSocket(';
  const guard = 'errors.Join(checkpointObserverRouteRequireInitialHostNamespace(), checkpointObserverRouteNestedFailureReducerControls())';
  const mutants = [
    ['nested bounded snapshot omitted', replaceRegionOnce(nodeKernel, diagnosticStart, controlsStart, 'output.snapshot()', 'output.String()')],
    ['nested typed Wait error inspection omitted', replaceRegionOnce(nodeKernel, diagnosticStart, controlsStart, 'errors.As(err, &child)', 'err != nil')],
    ['nested exact composed failure header substituted', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'const headerPrefix = "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture ("',
      'const headerPrefix = "--- FAIL: OtherTest ("')],
    ['nested fixed indented basename substituted', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'const source = "    checkpoint_local_observer_kernel_linux_test.go:"',
      'const source = " checkpoint_local_observer_kernel_linux_test.go:"')],
    ['nested continuation indentation weakened', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'const continuation = "            checkpoint_local_observer_kernel_linux_test.go:"',
      'const continuation = "    checkpoint_local_observer_kernel_linux_test.go:"')],
    ['nested synthetic continuation ownership unbound', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'continuationMatch[1] != ownedClient', 'false')],
    ['nested immediate continuation requirement removed', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'continuationCandidate && !strings.HasPrefix(line, continuation)', 'false')],
    ['nested unavailable client forged broker accepted', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'markerMatch[1] == "unavailable" && markerMatch[2] != "unavailable"', 'false')],
    ['tagged regexp import removed', replaceRegionOnce(nodeKernel, '\nimport (', '\nconst (', '"path/filepath"; "regexp"', '"path/filepath"')],
    ['nested incomplete cleanup pair accepted', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'passStage == 1 || passStage > 0 && runCount != 1', 'passStage > 0 && runCount != 1')],
    ['nested cleanup sentinels accepted without RUN', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd,
      'runCount != 1 || passStage != 0 || sawAssertion || closed', 'passStage != 0 || sawAssertion || closed')],
    ['nested canonical line bound widened', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd, 'number > 4800', 'number > 4801')],
    ['nested four-site inventory bound omitted', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd, 'seen[number] || len(sites) == 4', 'seen[number]')],
    ['nested summary window not closed', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd, 'collecting = false; closed = true', 'closed = true')],
    ['nested complete header scan weakened', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd, 'headers != 1 || invalid', 'headers > 1 || invalid')],
    ['nested capped site scan short-circuited', replaceRegionOnce(nodeKernel, reducerStart, reducerEnd, 'sites = append(sites, record[:separator])', 'sites = append(sites, record[:separator]); if len(sites) == 4 { break }')],
    ['nested actual Go controls omitted before effects', replaceRegionOnce(nodeKernel, outerStart, outerEnd, guard, 'checkpointObserverRouteRequireInitialHostNamespace()')],
    ['PID1 outer helper restored', replaceRegionOnce(nodeKernel, pid1Start, waitSocketStart, '\n\tif os.Getpid() != 1 || os.Geteuid() != 0 {', '\n\tt.Helper()\n\tif os.Getpid() != 1 || os.Geteuid() != 0 {')],
    ['PID1 failure closure helper omitted', replaceRegionOnce(nodeKernel, pid1Start, waitSocketStart, 'failRawLocalRoot := func(cause error) { t.Helper(); t.Fatalf(', 'failRawLocalRoot := func(cause error) { t.Fatalf(')],
  ];
  for (const [label, mutant] of mutants) {
    requireSource(mutant !== nodeKernel, `${label} mutant did not alter its source anchor`);
    let rejected;
    try { check(mutant); } catch (error) { rejected = error; }
    requireSource(rejected instanceof Error && rejected.message === `checkpoint observer route source contract failed: ${predicate}`,
      `${label} mutant missed the intended nested diagnostic source predicate`);
  }
}

function assertComposedFixtureIdentity(hostKernel, nodeKernel) {
  const hostUUID = hostKernel.match(/kernelFixtureUUID\s*=\s*"(GPU-[0-9A-Fa-f-]+)"/)?.[1];
  const hostPCI = hostKernel.match(/kernelFixturePCI\s*=\s*"([0-9A-Fa-f:.]+)"/)?.[1];
  const hostServer = functionBody(hostKernel, 'runCheckpointGPUObserverRouteServerChild(t *testing.T) {');
  const composed = functionBody(nodeKernel, 'checkpointObserverRouteComposedServerConfig(t *testing.T, workerPID int) checkpointLocalObserverRuntimeConfig {');
  const bridge = sources.get('internal/nodeagent/checkpoint_host_gpu_bridge_linux.go');
  const joined = hostUUID === 'GPU-00000000-0000-0000-0000-000000000019' && hostPCI === '0000:19:00.0' &&
    composed.includes(`plan, association := managedBindingFixture(); plan.Placement.PhysicalIdentity = "${hostUUID}"`) &&
    composed.includes('PhysicalIdentity: plan.Placement.PhysicalIdentity, ChildMaskUUID: plan.Placement.PhysicalIdentity') &&
    composed.includes('pin := &PinnedCheckpointLaunchPlan{plan: plan,') &&
    composed.includes('UUID: plan.Placement.PhysicalIdentity, PCI: "0000:19:00.0"') &&
    composed.includes('openPlan: func(context.Context) (*PinnedCheckpointLaunchPlan, error) { return pin, nil }') &&
    composed.includes('validatePlan: func(value *PinnedCheckpointLaunchPlan) (CheckpointLaunchPlan, error) { return value.Spec(), nil }') &&
    composed.includes('placement: func(context.Context, CheckpointLaunchPlan) (CheckpointDevicePlacement, error) { return placement, nil }') &&
    composed.includes('observeNestedManagedCheckpointFootprintUsing(ctx, pid, start, currentPlan, currentPlacement') &&
    composed.includes('readArgv: func(int) ([]string, error) { return managedCheckpointExpectedArgv(plan) }') &&
    hostServer.includes('devices: func(context.Context) ([]gpuDevice, error) {\n\t\t\treturn []gpuDevice{{UUID: kernelFixtureUUID, PCI: kernelFixturePCI}}, nil') &&
    hostServer.includes('processes: func(_ context.Context, pid int) ([]GPUProcess, error) {\n\t\t\treturn []GPUProcess{{PID: pid, UUID: kernelFixtureUUID, Bytes: 128 << 20}}, nil') &&
    bridge.includes('GPUUUID: placement.ChildMaskUUID, GPUPCI: pci');
  requireSource(joined, 'composed UUID/device/process join must propagate fixed host identity through placement, pinned plan, local inventory, and signed request');
}

function assertComposedFixture(hostKernel, nodeKernel) {
  assertComposedFixtureIdentity(hostKernel, nodeKernel);
  assertNestedFailureDiagnostic(nodeKernel);
  assertComposedFixtureGroupAuthority(nodeKernel, sources.get('internal/nodeagent/checkpoint_local_observer_linux.go'));
  assertComposedRootPathAdmission(nodeKernel);
  assertComposedClientPinHandoff(nodeKernel);
  assertPrivateExecutableTmpfs(nodeKernel, sources.get('internal/nodeagent/checkpoint_local_observer_linux_test.go'));
  assertTaggedRuntimeImport(nodeKernel);
  const hostServer = functionBody(hostKernel, 'runCheckpointGPUObserverRouteServerChild(t *testing.T) {');
  const hostParentCheck = functionBody(hostKernel, 'checkpointObserverRouteCheckHeldParent(fd int, path string) error {');
  const hostListenerCleanup = functionBody(hostKernel, 'checkpointObserverRouteCloseAndRemoveHostListener(listener **net.UnixListener, socketPath, parentPath string, parentFD, socketFD, socketPathFD *int, readyFile **os.File, readyPath string) error {');
  const namespaceFixture = functionBody(hostKernel, 'runCheckpointGPUObserverNestedPID1(t *testing.T) {');
  const outer = functionBody(nodeKernel, 'TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {');
  const nestedDiagnostic = functionBody(nodeKernel, 'checkpointObserverRouteNestedFailureDiagnostic(err error, output *checkpointLocalObserverLimitedBuffer) string {');
  const pid1 = functionBody(nodeKernel, 'checkpointObserverRouteComposedPID1(t *testing.T) {');
  const client = functionBody(nodeKernel, 'TestCheckpointObserverRouteComposedClientChild(t *testing.T) {');
  const broker = functionBody(nodeKernel, 'TestCheckpointObserverRouteComposedBrokerChild(t *testing.T) {');
  const brokerConfig = functionBody(nodeKernel, 'checkpointObserverRouteComposedServerConfig(t *testing.T, workerPID int) checkpointLocalObserverRuntimeConfig {');
  const parentDeath = functionBody(nodeKernel, 'checkpointObserverRouteParentDeathControl(executable string) (result error) {');
  const parentDeathParent = functionBody(nodeKernel, 'TestCheckpointObserverRouteParentDeathFixture(t *testing.T) {');
  const parentDeathProbe = functionBody(nodeKernel, 'TestCheckpointObserverRouteParentDeathProbe(t *testing.T) {');
  const localReapProof = functionBody(nodeKernel, 'checkpointObserverRouteCreatorLocallyReaped(output *checkpointLocalObserverLimitedBuffer, nonce string) bool {');
  const localReapAccept = functionBody(nodeKernel, 'checkpointObserverRouteAcceptLocalReap(output *checkpointLocalObserverLimitedBuffer, nonce string, committed bool) bool {');
  const noProbeProof = functionBody(nodeKernel, 'checkpointObserverRouteCreatorReportsNoProbe(output *checkpointLocalObserverLimitedBuffer, nonce string) bool {');
  const probeIdentity = functionBody(nodeKernel, 'checkpointObserverRouteCheckProbeIdentity(pid, parentPID int, executable string) error {');
  const socketSendBound = functionBody(nodeKernel, 'checkpointObserverRouteBoundSocketSend(fd int) error {');
  const prctlGetter = functionBody(nodeKernel, 'checkpointObserverRouteGetPrctlInt(option int) (int, error) {');
  const brokerReady = functionBody(nodeKernel, 'checkpointObserverRouteWaitForOutputMarker(output *checkpointLocalObserverLimitedBuffer, pidfd int, marker string, timeout time.Duration) error {');
  const exactLocalCleanup = functionBody(nodeKernel, 'checkpointObserverRouteRemoveExactLocalTree(root string, rootDev, rootInode uint64, pins []checkpointObserverRouteHeldPath, mounted ...*checkpointObserverRouteMountedCleanup) error {');
  const exactReaper = functionBody(nodeKernel, 'checkpointObserverRouteWaitExactChild(pidfd int, timeout time.Duration) (bool, error) {');
  const heldClose = functionBody(nodeKernel, 'checkpointObserverRouteCloseHeldPaths(pins []checkpointObserverRouteHeldPath) error {');
  const closeFD = functionBody(nodeKernel, 'checkpointObserverRouteCloseFD(fd *int) error {');
  const closeFile = functionBody(nodeKernel, 'checkpointObserverRouteCloseFile(file **os.File) error {');
  const publishClient = functionBody(nodeKernel, 'checkpointObserverRoutePublishClientBinaryUsing(source, destination string, destinationGID uint32,');
  const heldCheck = functionBody(nodeKernel, 'checkpointObserverRouteCheckHeldPaths(pins []checkpointObserverRouteHeldPath) error {');
  const treeControls = functionBody(nodeKernel, 'checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {');
  const treeBuilder = functionBody(nodeKernel, 'checkpointObserverRouteBuildLocalTreeControl(t *testing.T, suffix string, gid uint32) *checkpointObserverRouteControlTree {');
  const treeCleanup = functionBody(nodeKernel, '(tree *checkpointObserverRouteControlTree) cleanup() error {');
  const rootOwnerControls = functionBody(nodeKernel, 'checkpointObserverRouteLocalRootOwnerControls(t *testing.T) {');
  const adoptLocalRoot = functionBody(nodeKernel, 'checkpointObserverRouteAdoptLocalRootFD(rawFD *int, name string) (checkpointObserverRouteHeldPath, error) {');
  const sentinelControls = functionBody(nodeKernel, 'checkpointObserverRouteSentinelEarlyOwnerControls(t *testing.T) {');
  const sentinelOwner = functionBody(nodeKernel, '(owner *checkpointObserverRouteSentinelOwner) settle(cause error) error {');
  const sentinelSetup = functionBody(nodeKernel, 'checkpointObserverRouteSentinelSetup(file **os.File, contents []byte, ops checkpointObserverRouteSentinelOps) (uint64,uint64,error) {');
  requireSource(pid1.includes('checkpointObserverRouteRemoveExactLocalTree(localRoot,') &&
    pid1.includes('checkpointObserverRouteRemoveExactLocalTree(localRoot, localRootPin.dev, localRootPin.inode, localPins, mountedCleanup)') &&
    !pid1.includes('localRootStat') && pid1.includes('localCleanupUncertain') && exactLocalCleanup.includes('checkpointObserverRouteCheckHeldPaths(pins)'),
    'PID1 cleanup must recheck held entry identities and preserve unknown/substituted trees');
  requireSource(exactReaper.includes('unix.Waitid(unix.P_PIDFD, pidfd, &originalInfo, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)') &&
    exactReaper.includes('originalInfo.Signo != int32(syscall.SIGCHLD)') &&
    exactReaper.includes('syscall.Wait4(pid, &status, syscall.WNOHANG, nil)') &&
    exactReaper.includes('status.Signal() != syscall.SIGKILL') &&
    exactReaper.includes('return true, errors.New("adopted original probe was reaped without its exact parent-death SIGKILL")') &&
    exactReaper.includes('errors.Is(err, unix.EINTR)') && exactReaper.includes('errors.Is(err, syscall.EINTR)'),
    'exact subreaper must establish waitability through the original pidfd, settle consumed Wait independently of expected signal, and retry EINTR only within its deadline');
  requireSource(heldClose.includes('closeErr = errors.Join(closeErr, checkpointObserverRouteCloseHeldPath(&pins[index]))') &&
    nodeKernel.includes('checkpointObserverRouteCloseFD(&pin.fd)') &&
    closeFD.includes('owned := *fd') && closeFD.includes('*fd = -1\n\treturn unix.Close(owned)') && closeFD.split('unix.Close(owned)').length === 2 &&
    closeFile.includes('owned := *file') && closeFile.includes('*file = nil\n\treturn owned.Close()') &&
    publishClient.includes('owned := sourceFD; sourceFD = -1; result = errors.Join(result, unix.Close(owned))') &&
    publishClient.includes('owned := destinationFD; destinationFD = -1; result = errors.Join(result, unix.Close(owned))') &&
    nodeKernel.includes('pin := checkpointObserverRouteHeldPath{fd: -1}') &&
    nodeKernel.includes('errors.Join(err, checkpointObserverRouteCloseHeldPath(&pin))'),
    'fixture owners must join every held and publication descriptor close outcome exactly once');
  requireSource(heldCheck.includes('stat.Ino != pin.inode') && heldCheck.includes('held.Ino != pin.inode') &&
    heldCheck.includes('info.Mode()&os.ModeSymlink != 0') && heldCheck.includes('pin.isDir != info.IsDir()') &&
    heldCheck.includes('!pin.isDir && (uint64(held.Nlink) != pin.nlink || int64(held.Size) != pin.size)') &&
    heldCheck.includes('!pin.isDir && (uint64(stat.Nlink) != pin.nlink || info.Size() != pin.size)') &&
    exactLocalCleanup.includes('checkpointObserverRouteRequireExactNames(root, []string{"bin", "conf", "run", "signing"})'),
    'creation-time custody must hold stable directory identity, allow only known directory topology changes, keep file link/size strict, and reject substitutions/unknown names');
  requireSource(parentDeathParent.includes('probe.SysProcAttr = &syscall.SysProcAttr{PidFD: &probePIDFD, Pdeathsig: syscall.SIGKILL}') &&
    parentDeathParent.includes('probe.Start()') && parentDeathParent.includes('probeHandedOff = true') &&
    parentDeathParent.includes('runtime.LockOSThread()') && parentDeathParent.includes('"-test.timeout=7s"'),
    'parent-death probe must retain atomic creation pidfd custody, thread pin, live handoff and fixed child deadline');
  requireSource(parentDeath.includes('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL, nil, 0)') &&
    parentDeath.includes('status.Signal() != syscall.SIGKILL') &&
    parentDeath.includes('reaped, err := checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)\n\t\tif reaped { probeReaped = true }\n\t\tif err != nil { return err }'),
    'parent-death control must prove exact parent death and subreaper Wait before marking probe reaped');
  requireSource(prctlGetter.includes('unix.Prctl(option, uintptr(unsafe.Pointer(&value)), 0, 0, 0)') &&
    prctlGetter.includes('runtime.KeepAlive(&value)') && !nodeKernel.includes('PrctlRetInt(unix.PR_GET_CHILD_SUBREAPER') &&
    !nodeKernel.includes('PrctlRetInt(unix.PR_GET_PDEATHSIG'),
    'PR_GET child-subreaper and parent-death settings must use the kernel int* output ABI, not syscall return values');
  requireSource(parentDeath.includes('"ACK "+nonce') && parentDeath.includes('unix.SendmsgN(controlFD, []byte("ACK "+nonce)') &&
    parentDeath.includes('commitFlags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0') && parentDeath.includes('probeAckCommitted = true') &&
    parentDeath.indexOf('probeAckCommitted = true') < parentDeath.lastIndexOf('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL') &&
    parentDeathParent.includes('sent != len(commit)') &&
    parentDeathParent.includes('ackFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC)') && parentDeathParent.includes('ackControlN != 0') &&
    parentDeathParent.indexOf('unix.Recvmsg(controlFD, ack, ackControl, 0)') < parentDeathParent.indexOf('probeHandedOff = true') &&
    parentDeathParent.includes('sent != len(handoff)') && parentDeathParent.includes('SendmsgN(controlFD, commit, nil, nil, 0)') &&
    parentDeathParent.indexOf('probeHandedOff = true') < parentDeathParent.indexOf('SendmsgN(controlFD, commit, nil, nil, 0)') &&
    parentDeathParent.includes('go func() { probeDone <- probe.Wait() }()') &&
    parentDeathParent.includes('probe.Stdout, probe.Stderr = probeOutput, probeOutput') &&
    parentDeathParent.includes('checkpointObserverRouteWaitReadyLine(probeOutput, 3*time.Second)') &&
    !parentDeathParent.includes('probe.StdoutPipe()') &&
    parentDeathParent.includes('defer func() { fd := controlFD; controlFD = -1;') &&
    parentDeathParent.includes('checkpointObserverRouteBoundSocketSend(controlFD)') &&
    parentDeathParent.includes('unix.ParseSocketControlMessage(ackControl[:ackControlN])') &&
    parentDeathParent.includes('for _, fd := range ackRights { ackAncillaryErr = errors.Join(ackAncillaryErr, unix.Close(fd)) }') &&
    parentDeathParent.includes('checkpointObserverRouteCheckProbeIdentity(probe.Process.Pid, os.Getpid(), executable)') &&
    parentDeath.includes('"-test.timeout=15s"'),
    'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection');
  requireSource(parentDeath.includes('flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0') &&
    parentDeath.includes('probePIDFD, probeReaped, probeOwnershipTransferred = candidateProbePIDFD, false, true') && parentDeath.includes('parentDone != nil && !parentReaped') &&
    parentDeath.includes('17*time.Second') && parentDeath.includes('checkpointObserverRouteAcceptLocalReap(parentOutput, nonce, probeAckCommitted)') &&
    localReapAccept.includes('return !committed && checkpointObserverRouteCreatorLocallyReaped(output, nonce)') &&
    localReapProof.includes('strings.Count(string(parentText), marker) == 1') &&
    parentDeath.includes('if parentReaped && probeReaped {') &&
    parentDeath.indexOf('probePIDFD, probeReaped, probeOwnershipTransferred = candidateProbePIDFD, false, true') < parentDeath.indexOf('unix.SendmsgN(controlFD, []byte("ACK "+nonce)') &&
    parentDeath.includes('closeReceived())') && parentDeath.includes('ancillaryErr = errors.Join(ancillaryErr, rightsErr)') &&
    parentDeath.includes('if checkpointObserverRouteAcceptLocalReap(parentOutput, nonce, probeAckCommitted) { probeReaped = true }') &&
    parentDeath.includes('checkpointObserverRouteCheckProbeIdentity(probePID, parent.Process.Pid, executable)') &&
    parentDeath.includes('if !probeOwnershipTransferred && checkpointObserverRouteCreatorReportsNoProbe(parentOutput, nonce) { probeReaped = true }') &&
    localReapProof.includes('CHECKPOINT_OBSERVER_ROUTE_PROBE_LOCAL_REAPED "+nonce+" STATUS=') &&
    localReapAccept.includes('return !committed && checkpointObserverRouteCreatorLocallyReaped(output, nonce)') &&
    noProbeProof.includes('CHECKPOINT_OBSERVER_ROUTE_NO_CHILD "+nonce') &&
    probeIdentity.includes('processStat.Uid != parentStat.Uid') && probeIdentity.includes('processStat.Gid != parentStat.Gid') &&
    probeIdentity.includes('os.SameFile(executableInfo, processExecutable)') &&
    probeIdentity.includes('[]string{"pid", "user", "mnt"}') &&
    socketSendBound.includes('unix.SO_SNDTIMEO'),
    'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore');
  requireSource(hostServer.includes('handleObserverConnectionUsing(context.Background(), connection, config') &&
    hostServer.includes('index < 2') && hostServer.includes('devices: func') && hostServer.includes('processes: func') &&
    hostServer.includes('Bytes: 128 << 20') && hostServer.includes('CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2'),
    'outer CPU child must run the actual host handler twice against synthetic inventory only');
  requireSource(outer.includes('hostParentFD, err := unix.Dup(hostPins[1].fd)') &&
    outer.includes('server.ExtraFiles = []*os.File{hostParentFile}') &&
    outer.includes('CHECKPOINT_OBSERVER_ROUTE_HOST_PARENT_FD=3') &&
    outer.includes('checkpointObserverRouteCloseFile(&hostParentFile)') &&
    outer.includes('hostPins = append(hostPins, hostDirPin)') && outer.includes('hostDirPin.fd = -1'),
    'host server must receive and settle the original creation-time protected parent capability, not reopen a late snapshot');
  requireSource(hostServer.includes('unix.Open(socketPath, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)') &&
    hostServer.includes('listener.SetUnlinkOnClose(false)') &&
    hostServer.includes('checkpointObserverRouteCheckHeldParent(parentFD, parentPath)') &&
    hostServer.includes('parentFD = -1') &&
    hostServer.includes('host socket parent capability close outcome is uncertain') &&
    hostServer.indexOf('parentFD, err := strconv.Atoi(os.Getenv(kernelFixtureRouteParentFDEnv))') < hostServer.indexOf('defer func() {') &&
    hostServer.indexOf('defer func() {') < hostServer.indexOf('configBytes, err := os.ReadFile(configPath)') &&
    hostServer.indexOf('checkpointObserverRouteCheckHeldParent(parentFD, parentPath)') < hostServer.indexOf('configBytes, err := os.ReadFile(configPath)') &&
    hostServer.lastIndexOf('checkpointObserverRouteCheckHeldParent(parentFD, parentPath)') > hostServer.indexOf('privateBytes, err := os.ReadFile(keyPath)') &&
    hostServer.lastIndexOf('checkpointObserverRouteCheckHeldParent(parentFD, parentPath)') < hostServer.indexOf('net.ListenUnix("unix"') &&
    hostServer.includes('checkpointObserverRouteCloseAndRemoveHostListener(&listener, socketPath, parentPath, &parentFD,') &&
    hostParentCheck.includes('host socket parent path no longer names the original held directory') &&
    hostParentCheck.includes('uint64(stat.Dev) != held.Dev || stat.Ino != held.Ino') &&
    hostParentCheck.includes('info.Mode()&os.ModeSymlink != 0') &&
    hostParentCheck.includes('held.Mode&0777 != 0700') &&
    hostServer.includes('socketPathFD := -1') &&
    hostListenerCleanup.includes('unix.Fstat(*socketFD, &listenerStat)') && hostListenerCleanup.includes('socketCustodyValid') &&
    hostListenerCleanup.includes('checkpointObserverRouteCheckHeldParent(*parentFD, parentPath)') &&
    hostListenerCleanup.includes('*parentFD = -1') &&
    hostListenerCleanup.includes('if parentFD != nil && *parentFD >= 0 { owned := *parentFD; *parentFD = -1; result = errors.Join(result, unix.Close(owned)) }') &&
    hostListenerCleanup.includes('checkpointObserverRouteCheckHeldNamedObject(*socketPathFD, socketPath, unix.S_IFSOCK)') &&
    hostListenerCleanup.includes('*listener = nil') && hostListenerCleanup.includes('*socketFD = -1') &&
    hostListenerCleanup.includes('*socketPathFD = -1') && hostListenerCleanup.includes('*readyFile = nil') &&
    hostListenerCleanup.includes('closeErr := owned.Close()\n\t\tresult = errors.Join(result, closeErr)\n\t\tlistenerClosed = closeErr == nil') &&
    hostListenerCleanup.includes('result = errors.Join(result, owned.Close())') &&
    hostListenerCleanup.includes('os.Remove(socketPath)') &&
    hostServer.includes('cleanupErr := cleanup()') && hostServer.includes('errors.Join(err, cleanupErr)') &&
    hostServer.indexOf('if err := cleanup(); err != nil') < hostServer.indexOf('CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2'),
    'actual host owner joins listener, socket and ready-file settlement before its success marker');
  requireSource(pid1.includes('checkpointObserverRouteWaitForOutputMarker(brokerOutput, brokerPIDFD, "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS", 3*time.Second)') &&
    brokerReady.includes('output.snapshot()') && brokerReady.includes('if count > 1') &&
    brokerReady.includes('strings.Count(string(stable), marker) != 1') &&
    brokerReady.includes('checkpointLocalPIDFDAlive(pidfd)') && brokerReady.includes('child readiness marker missed its fixed deadline'),
    'bounded broker readiness requires a stable exact-once output marker, live original pidfd, overflow and deadline checks');
  requireSource(namespaceFixture.includes('worker.SysProcAttr = &syscall.SysProcAttr{PidFD: &workerPIDFD}'),
    'nested namespace fixture worker lacks atomic creation-time pidfd custody');
  requireSource(namespaceFixture.includes('if err := worker.Start(); err != nil') &&
    namespaceFixture.includes('go func() { workerDone <- worker.Wait() }()'),
    'nested namespace fixture worker does not register its exact Wait immediately after Start');
  requireSource(namespaceFixture.includes('unix.PidfdSendSignal(workerPIDFD, syscall.SIGKILL, nil, 0)') &&
    namespaceFixture.includes('workerReaped = true'),
    'nested namespace fixture worker lacks held-pidfd termination and confirmed Wait/reap');
  requireSource(!namespaceFixture.includes('worker.Process.Kill()'),
    'nested namespace fixture worker has a forbidden numeric kill fallback');
  requireSource(outer.includes('checkpointObserverRouteRequireInitialHostNamespace') &&
    outer.includes('exec.Command(serverExecutable') && nodeKernel.includes('CHECKPOINT_OBSERVER_ROUTE_HOST_TEST_BINARY') &&
    outer.includes('checkpointObserverRouteValidateHostBinary(hostBinary)') &&
    outer.includes('checkpointObserverRouteRemoveExactPrivateTree(root, hostDir') &&
    pid1.includes('checkpointObserverRouteRemoveExactLocalTree(localRoot') &&
    outer.includes('CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNS | unix.CLONE_NEWCGROUP') &&
    outer.includes('TestCheckpointObserverRouteComposedKernelFixture') && outer.includes('PidFD:') && outer.includes('preservePrivateRoot'),
    'one fixed host parent must connect the actual route-server child to a nested root collector and preserve uncertain custody');
  const validateHostBinary = functionBody(nodeKernel, 'checkpointObserverRouteValidateHostBinary(binary string) (result error) {');
  requireSource(validateHostBinary.includes('filepath.Base(binary) != "checkpoint-observer-host.test"') &&
    validateHostBinary.includes('checkpoint-observer-route-build-') && validateHostBinary.includes('checkpoint-observer-route-upload-') && validateHostBinary.includes('dirInfo.Mode().Perm() != 0700') &&
    validateHostBinary.includes('info.Mode().IsRegular()') && validateHostBinary.includes('stat.Nlink != 1') &&
    validateHostBinary.includes('stat.Uid != 0') && validateHostBinary.includes('unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW') &&
    validateHostBinary.includes('result = errors.Join(result, unix.Close(owned))'),
    'host test executable is not pinned to the private bounded root-owned build directory and held file identity');
  const observerOrdinary = sources.get('internal/nodeagent/checkpoint_local_observer_linux_test.go');
  requireSource(brokerConfig.includes('var records [2]string; recordCount, sinkOverflow := 0, false; binding, err, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, func(record string) { if recordCount >= len(records) { sinkOverflow = true; return }; records[recordCount] = record; recordCount++ }, observeCheckpointManagedBindingLinux); for _, record := range checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid) { fmt.Println(record) }') &&
    observerOrdinary.includes('func checkpointObserverRouteCollectorTrace(') &&
    brokerConfig.includes('observeCheckpointHostGPUAttributionLocalObserverUsing') &&
    brokerConfig.includes('composed fixture must not use local direct inventory') && broker.includes('checkpointLocalObserverRunWithConfig(ctx, config)') &&
    broker.includes('os.Getpid() <= 1 || os.Geteuid() != 0') && broker.includes('signal.NotifyContext') &&
    pid1.includes('brokerPIDFD') && pid1.includes('broker.Process.Pid <= 1') && pid1.includes('unix.PidfdSendSignal(brokerPIDFD, syscall.SIGTERM'),
    'nested root collector uses a held root broker child PID greater than one, real peer credentials, and finite pidfd/reap cleanup');
  requireSource(pid1.includes('localRoot := os.Getenv(checkpointObserverRouteLocalRootEnv)') &&
    pid1.includes('checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID)') &&
    pid1.includes('exec.Command(clientExecutable') && nodeKernel.includes('unix.Fchmod(destinationFD, 0555)') &&
    nodeKernel.includes('unix.O_NOFOLLOW') && nodeKernel.includes('unix.Fchown(destinationFD, 0, int(destinationGID))') &&
    nodeKernel.includes('heldDestination.Gid != destinationGID') && nodeKernel.includes('unix.Pread(destinationFD, publishedBytes[offset:]') &&
    !pid1.includes('checkpointLocalExecutableIdentity("/proc/self")') &&
    nodeKernel.includes('checkpointObserverRouteRequireExactNames(root, []string{"bin", "conf", "run", "signing"})'),
    'unprivileged client must execute the published path after actual held-file bytes, owner, group, mode and digest checks');
  requireSource(outer.includes('checkpointObserverRouteHoldRunParent()') && outer.includes('os.MkdirTemp("/run", "checkpoint-observer-route-fixture-")') &&
    outer.includes('os.MkdirTemp("/run", "checkpoint-observer-route-local-")') && outer.includes('checkpointObserverRouteRequireHeldRunParent(runDev, runInode)'),
    'fixture host and local roots use pinned root-owned nonwritable /run ancestry');
  requireSource(outer.indexOf('fmt.Println("CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY")') >
    outer.indexOf('checkpointObserverRouteCloseHeldPaths(hostPins)') &&
    outer.includes('checkpointObserverRouteCloseHeldPath(&localRootPin)') &&
    outer.split('checkpointObserverRouteCloseHeldPath(&localRootPin)').length === 3 &&
    outer.split('checkpointObserverRouteCloseFD(&runParentFD)').length === 3 &&
    outer.lastIndexOf('if closeErr := checkpointObserverRouteCloseHeldPath(&localRootPin); closeErr != nil') < outer.indexOf('fmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS")') &&
    outer.lastIndexOf('if closeErr := checkpointObserverRouteCloseFD(&runParentFD); closeErr != nil') < outer.indexOf('fmt.Println("CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY")'),
    'composed success marker follows local-root and host creation-custody descriptor settlement');
  requireSource(outer.includes('checkpointObserverRouteCaptureHeldPath(root)') && outer.includes('checkpointObserverRouteCaptureHeldPath(hostDir)') &&
    outer.includes('checkpointObserverRouteCaptureHeldPath(localRoot)') && outer.includes('checkpointObserverRouteLocalRootFDEnv + "=3"') &&
    pid1.includes('checkpointObserverRouteAdoptLocalRootFD(&localRootRawFD, localRoot)') &&
    pid1.includes('checkpointObserverRouteCaptureHeldPath(dir)') && pid1.includes('checkpointObserverRouteCreateHeldFixtureFile(item.path, item.data, 0, item.gid, item.mode)') &&
    pid1.includes('checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID)') &&
    pid1.includes('checkpointObserverRouteRemoveExactLocalTree(localRoot,') &&
    nodeKernel.includes('type checkpointObserverRouteHeldPath struct') && nodeKernel.includes('fd int') &&
    nodeKernel.includes('checkpointObserverRouteCheckHeldPaths(pins)') && nodeKernel.includes('checkpointObserverRouteCloseHeldPaths(hostPins)') &&
    nodeKernel.includes('unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW') &&
    pid1.includes('localPins = append(localPins, pin)') && pid1.includes('checkpointObserverRouteRefreshHeldPath(&localPins[index])') &&
    outer.indexOf('hostPins = append(hostPins, rootPin)') >= 0 && outer.indexOf('hostPins = append(hostPins, rootPin)') < outer.indexOf('os.Chmod(root, 0700)') &&
    outer.indexOf('defer func() { if closeErr := checkpointObserverRouteCloseHeldPath(&localRootPin)') < outer.indexOf('os.Chmod(localRoot, 0711)') &&
    pid1.includes('localRootPin.dev, localRootPin.inode'),
    'each host/local entry retains its original creation descriptor through publication, policy, launch and exact cleanup; PID1 receives the outer local-root capability');
  requireSource(outer.includes('errors.Join(err, closeErr)') && outer.includes('checkpointObserverRouteCloseFile(&localRootFile)') &&
    outer.includes('could not start exact nested route fixture child: %v", errors.Join(err, closeErr)') &&
    pid1.indexOf('checkpointObserverRouteCaptureHeldPath(dir)') < pid1.indexOf('localPins = append(localPins, pin)') &&
    pid1.indexOf('localPins = append(localPins, pin)') < pid1.indexOf('os.Chown(item.path, 0, int(item.gid))') &&
    outer.indexOf('hostPins = append(hostPins, rootPin)') < outer.indexOf('os.Chmod(root, 0700)'),
    'every acquired directory/file owner is registered before subsequent fallible metadata work, and nested-start close errors remain joined');
  const localTreeCleanup = 'checkpointObserverRouteRemoveExactLocalTree(localRoot, localRootPin.dev, localRootPin.inode, localPins, mountedCleanup)';
  requireSource(pid1.indexOf(localTreeCleanup) > pid1.indexOf('checkpointObserverRouteCaptureHeldPath(dir)') &&
    pid1.indexOf(localTreeCleanup) > pid1.indexOf('checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID)') &&
    pid1.indexOf(localTreeCleanup) > pid1.indexOf('checkpointObserverRouteCreateHeldFixtureFile(item.path, item.data, 0, item.gid, item.mode)') &&
    pid1.indexOf(localTreeCleanup) > pid1.indexOf('if localCleanupUncertain { t.Fatal("a child owner is uncertain; exact local-tree removal is suppressed") }'),
    'the real populated local-tree cleanup positive follows original directory/file pinning and settled child owners before any bounded mutation controls');
  requireSource(outer.includes('checkpointObserverRouteLocalTreeCustodyControls(t)') &&
    treeControls.indexOf('positive:=checkpointObserverRouteBuildLocalTreeControl(t,"positive",gid)') >= 0 && treeControls.indexOf('positive:=checkpointObserverRouteBuildLocalTreeControl(t,"positive",gid)') < treeControls.indexOf('for _,kind:=range []string{"directory","file","unknown"}') &&
    treeControls.indexOf('checkpointObserverRouteCheckHeldPaths(positive.pins)') < treeControls.indexOf('checkpointObserverRouteRemoveExactLocalTree(positive.root,positive.rootDev,positive.rootInode,positive.pins)') && treeControls.indexOf('checkpointObserverRouteRemoveExactLocalTree(positive.root,positive.rootDev,positive.rootInode,positive.pins)') < treeControls.indexOf('for _,kind:=range []string{"directory","file","unknown"}') &&
    treeControls.includes('checkpointObserverRouteCheckHeldPaths(original)') && treeControls.includes('checkpointObserverRouteRemoveExactLocalTree(root,tree.rootDev,tree.rootInode,original)') &&
    treeControls.includes('if err==nil||!strings.Contains(err.Error(),"held creation-time inode")') && treeControls.includes('strings.Contains(err.Error(),"unexpected")') &&
    treeControls.includes('case "directory":') && treeControls.includes('case "file":') && treeControls.includes('case "unknown":') &&
    treeControls.includes('same-shaped changed-inode %s missed intended custody error') && treeControls.includes('directory substitution did not preserve its creation-time original') && treeControls.includes('file substitution did not preserve its creation-time original') && treeControls.includes('unknown topology object was not preserved') &&
    treeBuilder.includes('tree.pins=append(tree.pins,pin)') && treeBuilder.includes('t.Cleanup(func(){ if err := tree.cleanup()') &&
    treeCleanup.includes('checkpointObserverRouteCheckHeldPaths([]checkpointObserverRouteHeldPath{*pin})') && treeCleanup.includes('os.Remove(pin.path)') &&
    treeControls.includes('CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS'),
    'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives');
  requireSource(pid1.includes('localRootRawFD := 3') && pid1.indexOf('localRootRawFD := 3') >= 0 && pid1.indexOf('localRootRawFD := 3') < pid1.indexOf('unix.Mount(') &&
    pid1.indexOf('defer func() { if closeErr := checkpointObserverRouteCloseFD(&localRootRawFD)') < pid1.indexOf('unix.Mount(') &&
    pid1.includes('errors.Join(cause, checkpointObserverRouteCloseFD(&localRootRawFD))') &&
    pid1.includes('checkpointObserverRouteAdoptLocalRootFD(&localRootRawFD, localRoot)') &&
    adoptLocalRoot.indexOf('checkpointObserverRouteHeldPathFromFD(name, *rawFD)') < adoptLocalRoot.indexOf('*rawFD = -1') &&
    adoptLocalRoot.includes('pin.mode&0777 != 0711') &&
    rootOwnerControls.includes('checkpointObserverRouteAdoptLocalRootFD(&raw, root)') &&
    rootOwnerControls.includes('adoptedOwner := adopted') && rootOwnerControls.indexOf('t.Cleanup(func() { if closeErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner)') >= 0 && rootOwnerControls.indexOf('t.Cleanup(func() { if closeErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner)') < rootOwnerControls.indexOf('realCloseErr := checkpointObserverRouteCloseHeldPath(&pin)') &&
    rootOwnerControls.includes('adoptedCloseErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner)') && rootOwnerControls.includes('errors.Join(closeErr, adoptedCloseErr)') && rootOwnerControls.includes('realCloseErr != nil || adoptedCloseErr != nil') && rootOwnerControls.includes('explicit old-pin close outcome injection') &&
    rootOwnerControls.includes('pin = adoptedOwner; adoptedOwner.fd = -1') && rootOwnerControls.includes('close-error settlement changed the original named root') &&
    rootOwnerControls.includes('checkpointObserverRouteAdoptLocalRootFD(&raw, filepath.Join(root, "substituted"))') &&
    rootOwnerControls.includes('checkpointObserverRouteCloseFD(&raw)') && rootOwnerControls.includes('raw != -1') &&
    rootOwnerControls.includes('if closeErr := checkpointObserverRouteCloseFD(&raw); closeErr != nil || raw != -1') && rootOwnerControls.includes('t.Cleanup(func() {'),
    'PID1 must own inherited FD3 before every fallible check and exercise actual validation-failure and successful transfer controls');
  const checkedChildCloseSites = [
    ['clientPIDFD','unprivileged client original pidfd settlement failed','unprivileged client pidfd close failed'],
    ['brokerPIDFD','local broker original pidfd settlement failed','root broker pidfd close failed'],
    ['workerPIDFD','composed worker pidfd settlement failed','composed worker pidfd close failed'],
  ];
  for (const [owner, message, deferredMessage] of checkedChildCloseSites) {
    const statement = `if closeErr := checkpointObserverRouteCloseFD(&${owner}); closeErr != nil { localCleanupUncertain = true; t.Fatalf("${message}: %v", closeErr) }`;
    const deferred = `if closeErr := checkpointObserverRouteCloseFD(&${owner}); closeErr != nil { localCleanupUncertain = true; t.Errorf("${deferredMessage}: %v", closeErr) }`;
    requireSource(pid1.split(statement).length === 2 && pid1.indexOf(statement) < pid1.indexOf(localTreeCleanup) && pid1.includes(deferred),
      'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
  }
  requireSource(outer.includes('checkpointObserverRouteSentinelEarlyOwnerControls(t)') &&
    outer.includes('checkpointObserverRouteSentinelSetup(&sentinelFile,sentinelBytes,checkpointObserverRouteRealSentinelOps(sentinelFile))') &&
    outer.indexOf('defer func() { if closeErr := checkpointObserverRouteCloseFile(&sentinelFile)') < outer.indexOf('checkpointObserverRouteSentinelSetup(') &&
    sentinelSetup.includes('errors.Join(cause,ops.close(file))') && ['if err:=ops.chmod();err!=nil{return settle(err)}','if n,err:=ops.write(contents);err!=nil{return settle(err)}','if err:=ops.sync();err!=nil{return settle(err)}','if err!=nil{return settle(err)}'].every(branch => sentinelSetup.includes(branch)) &&
    sentinelSetup.includes('stat.Uid!=0||info.Mode().Perm()!=0600||info.Size()!=int64(len(contents))') &&
    sentinelControls.includes('checkpointObserverRouteSentinelOwner{file:file,path:file.Name(),active:true,close:checkpointObserverRouteCloseFile}') &&
    sentinelControls.includes('checkpointObserverRouteSentinelSetup(&owner.file,[]byte("sentinel-owner-control\\n"),ops)') &&
    sentinelControls.includes('owner.dev,owner.inode,owner.known=uint64(held.Dev),held.Ino,true') && sentinelOwner.includes('if !owner.known{return errors.Join(cause,result,errors.New("sentinel original identity unknown; preserving name"))}') &&
    ['chmod','write','sync','stat'].every(stage => sentinelControls.includes('if fault=="'+stage+'"')) && sentinelControls.includes('checkpointObserverRouteBadModeInfo{info}') &&
    sentinelControls.includes('explicit injected sentinel close error') && sentinelControls.includes('owner.settle(err)') && sentinelControls.includes('if fault=="chmod"{expected=""}') && !sentinelControls.includes('fault=="chmod"||fault=="write"') &&
    sentinelControls.indexOf('owner,err:=run("",false)') < sentinelControls.indexOf('for _,fault:=range []string{"chmod","write","sync","stat","identity"}') &&
    outer.includes('checkpointObserverRouteCloseFile(&sentinelFile); closeErr != nil { t.Errorf("could not settle exact outside sentinel descriptor') &&
    outer.indexOf('checkpointObserverRouteCloseFile(&sentinelFile); closeErr != nil { t.Errorf("could not settle exact outside sentinel descriptor') < outer.indexOf('os.Remove(sentinelPath)'),
    'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  requireSource(pid1.includes('{os.Getenv(checkpointObserverRouteLocalPolicyEnv), policyBytes, groupID, 0600}') &&
    pid1.includes('{os.Getenv(checkpointObserverRouteLocalPublicEnv), public, groupID, 0640}') &&
    pid1.includes('checkpointObserverRouteCreateHeldFixtureFile(item.path, item.data, 0, item.gid, item.mode)') &&
    nodeKernel.includes('{filepath.Join(confDir, "policy.json"), 0600, groupID, 64 << 10}') &&
    nodeKernel.includes('{filepath.Join(confDir, "observer.pub"), 0640, groupID, 4096}'),
    'root local policy remains exact0600 while its separate public key remains0640');
  requireSource(outer.includes('checkpoint-observer-route-sentinel-') && outer.includes('outside sentinel contents changed') &&
    outer.includes('CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS') &&
    outer.includes('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS') &&
    pid1.includes('Pdeathsig: syscall.SIGKILL') && pid1.includes('brokerReaped') &&
    parentDeath.includes('unix.PR_SET_CHILD_SUBREAPER') && parentDeath.includes('unix.Recvmsg(controlFD, data, oob, unix.MSG_CMSG_CLOEXEC)') &&
    parentDeath.includes('unix.ParseUnixRights') && parentDeath.includes('checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)') &&
    parentDeath.includes('unix.PidfdSendSignal(parentPIDFD, syscall.SIGKILL') && parentDeath.includes('status.Signal() != syscall.SIGKILL') &&
    parentDeath.includes('parentReaped = true') && parentDeath.includes('probeReaped = true') &&
    parentDeathParent.includes('probe.SysProcAttr = &syscall.SysProcAttr{PidFD: &probePIDFD, Pdeathsig: syscall.SIGKILL}') &&
    parentDeathParent.includes('runtime.LockOSThread()') && parentDeathProbe.includes('unix.PR_GET_PDEATHSIG') &&
    nodeKernel.includes('func checkpointObserverRouteWaitExactChild(pidfd int, timeout time.Duration) (bool, error)') &&
    nodeKernel.includes('syscall.Wait4(pid, &status, syscall.WNOHANG, nil)'),
    'composed fixture preserves an outside sentinel and proves parent death plus exact-child subreaper Wait4 using transferred original pidfd custody');
  requireSource(client.includes('routeCheckpointManagedBindingObserver(ctx, os.Geteuid()') &&
    client.includes('checkpointLocalObserverObserveWithConfig') && client.includes('CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS') &&
    pid1.includes('exec.Command(workerExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedBrokerChild$"') &&
    pid1.includes('exec.Command(clientExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedClientChild$"'),
    'nested unprivileged client must perform the actual signed local IPC route, not a disconnected synthetic callback');
}

function assertPrivateExecutableTmpfs(nodeKernel, linuxTest) {
  const pid1 = functionBody(nodeKernel, 'checkpointObserverRouteComposedPID1(t *testing.T) {');
  const cleanup = functionBody(nodeKernel, 'checkpointObserverRouteRemoveExactLocalTree(root string, rootDev, rootInode uint64, pins []checkpointObserverRouteHeldPath, mounted ...*checkpointObserverRouteMountedCleanup) error {');
  const mount = functionBody(linuxTest, 'checkpointObserverRouteMountPrivateExecutableBin(root, bin string, rootFD int, rootDev, rootInode uint64, binFD int, binDev, binInode uint64) (*checkpointObserverRouteTmpfsMount, error) {');
  const options = functionBody(linuxTest, 'checkpointObserverRouteTmpfsOptions() string {');
  const mountInfo = functionBody(linuxTest, 'checkpointObserverRouteTmpfsMountInfo(raw, target string) (uint64, bool) {');
  const controls = functionBody(linuxTest, 'TestCheckpointObserverRouteTmpfsCustodyControls(t *testing.T) {');
  const closeReference = functionBody(linuxTest, 'checkpointObserverRouteTmpfsCloseReferenceUsing(mount *checkpointObserverRouteTmpfsMount, descriptor *int, closeFD func(int) error) error {');
  const settle = functionBody(linuxTest, 'checkpointObserverRouteTmpfsSettleReferencesUsing(mount *checkpointObserverRouteTmpfsMount, clientFD, mountedRootFD *int, closeFD func(int) error) error {');
  const proof = functionBody(linuxTest, 'checkpointObserverRouteTmpfsSettledProof(cleanup *checkpointObserverRouteMountedCleanup) (*checkpointObserverRouteTmpfsUnmountProof, error) {');
  const unmountUsing = functionBody(linuxTest, 'checkpointObserverRouteTmpfsUnmountUsing(mount *checkpointObserverRouteTmpfsMount, proof *checkpointObserverRouteTmpfsUnmountProof, unmount func(string, int) error) error {');
  const unmountFailureGate = 'if err := checkpointObserverRouteTmpfsUnmountUsing(mountCleanup.mount, proof, unix.Unmount); err != nil { return err }';
  const cleanupPropagatesUnmountError = (candidate) => candidate.includes(unmountFailureGate) &&
    candidate.indexOf(unmountFailureGate) < candidate.indexOf('checkpointObserverRouteRevealedUnderlyingBinCurrent(mountCleanup)');
  const eligibleName = 'checkpointObserverRouteTmpfsUnmountEligible';
  const eligibleCount = topLevelGoFunctionCounts(linuxTest).get(eligibleName) ?? 0;
  requireSource(hasUniqueTopLevelGoFunctions(linuxTest) && eligibleCount === 1,
    'ordinary Linux test declarations must be derived from top-level functions and the proof-based unmount eligibility function must be unique');
  const duplicateEligible = '\nfunc checkpointObserverRouteTmpfsUnmountEligible(mount *checkpointObserverRouteTmpfsMount, childrenClear, custodyCurrent bool) bool { return mount != nil && childrenClear && custodyCurrent }\n';
  requireSource(!hasUniqueTopLevelGoFunctions(linuxTest + duplicateEligible),
    'exact duplicate old-signature unmount eligibility mutant was not rejected');
  const exactTmpfsOptions = 'checkpointObserverRouteTmpfsSize  = "size=128M,nr_inodes=128,mode=0711,uid=0,gid=0"';
  requireSource(fixedPrivateTmpfsBuilderAccepts(linuxTest),
    'the exact root-owned tmpfs positive is not derived from the production builder wired to the actual mount call');
  for (const [label, value] of [
    ['missing explicit uid=0', 'size=128M,nr_inodes=128,mode=0711,gid=0'],
    ['missing explicit gid=0', 'size=128M,nr_inodes=128,mode=0711,uid=0'],
    ['nonroot uid=1', 'size=128M,nr_inodes=128,mode=0711,uid=1,gid=0'],
    ['nonroot gid=1', 'size=128M,nr_inodes=128,mode=0711,uid=0,gid=1'],
  ]) {
    requireSource(fixedPrivateTmpfsBuilderAccepts(linuxTest), `${label} mutant lacks its known-positive source control`);
    requireSource(linuxTest.split(exactTmpfsOptions).length === 2, `${label} mutant source anchor is not unique`);
    const optionMutant = linuxTest.replace(exactTmpfsOptions, `checkpointObserverRouteTmpfsSize  = "${value}"`);
    requireSource(!fixedPrivateTmpfsBuilderAccepts(optionMutant), `${label} actual production-builder mutant was not rejected`);
  }
  requireSource(options.includes('return checkpointObserverRouteTmpfsSize') && linuxTest.includes(exactTmpfsOptions) &&
    mount.includes('os.Getpid() != 1') && mount.includes('os.Geteuid() != 0') && mount.includes('checkpointObserverRouteMountNamespacePrivate()') &&
    mount.includes('bin != filepath.Join(root, "bin")') && mount.includes('unix.Fstat(rootFD') && mount.includes('unix.Fstat(binFD') &&
    mount.includes('heldRoot.Ino != rootInode') && mount.includes('heldBin.Ino != binInode') && mount.includes('pathStat.Ino != mounted.Ino') &&
    mount.includes('os.ReadDir(bin)') && mount.includes('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions())') &&
    mount.includes('unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY') && mount.includes('unix.Fstatfs(mount.fd, &fs)') &&
    mount.includes('uint64(fs.Type) != checkpointObserverRouteTmpfsMagic') && mount.includes('fs.Blocks*uint64(fs.Bsize) != 128<<20') && mount.includes('fs.Files != 128') &&
    mount.includes('checkpointObserverRouteTmpfsMountInfo(string(mountInfo), bin)') && mountInfo.includes('fields[separator+1] != "tmpfs"') &&
    mount.indexOf('unix.Fstat(rootFD') < mount.indexOf('unix.Fstat(binFD') && mount.indexOf('os.ReadDir(bin)') < mount.indexOf('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV') &&
    mount.indexOf('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV') < mount.indexOf('unix.Open(bin, unix.O_PATH') &&
    mount.indexOf('unix.Open(bin, unix.O_PATH') < mount.indexOf('unix.Fstatfs(mount.fd, &fs)') && mount.indexOf('unix.Fstatfs(mount.fd, &fs)') < mount.indexOf('checkpointObserverRouteTmpfsMountInfo(string(mountInfo), bin)') &&
    mountInfo.includes('seenMount[option]') && mountInfo.includes('seenSuper[key]') && mountInfo.includes('superValues["size"] != "131072k"') &&
    mountInfo.includes('(seenSuper["uid"] && superValues["uid"] != "0")') && mountInfo.includes('(seenSuper["gid"] && superValues["gid"] != "0")'),
    'private fixture tmpfs requires root PID1/private namespace, exact held custody, realistic bounded kernel serialization, default root ownership, and current mount identity');
  requireSource(pid1.includes('checkpointObserverRouteMountPrivateExecutableBin(localRoot, binDir, localPins[0].fd, localRootPin.dev, localRootPin.inode, localPins[4].fd, localPins[4].dev, localPins[4].inode)') &&
    pid1.indexOf('checkpointObserverRouteMountPrivateExecutableBin(') < pid1.indexOf('checkpointObserverRoutePublishClientBinaryHeld(') &&
    pid1.includes('checkpointObserverRouteCaptureHeldPath(binDir)') && pid1.includes('localPins = append(localPins, mountedRootPin)') &&
    pid1.includes('checkpointObserverRouteTmpfsTrackReference(mountedBin)') && pid1.includes('clientFD: &localPins[clientPinIndex].fd') &&
    pid1.includes('mountedRootFD: &localPins[mountedRootPinIndex].fd') && pid1.includes('rootFD: localPins[0].fd') && pid1.includes('childrenClear: true'),
    'mount-root and client descriptor ownership is tracked in caller-owned pins while original root/bin capabilities remain held');
  requireSource(mountInfo.includes('key != "inode32" && key != "inode64"') && mountInfo.includes('seenSuper["inode32"] && seenSuper["inode64"]') &&
    controls.includes('inode64') && controls.includes('noInodeMode') && controls.includes('inode32Info') &&
    controls.includes('conflicting-inode-modes') && controls.includes('duplicate-inode64') && controls.includes('duplicate-inode32') &&
    controls.includes('malformed-inode64') && controls.includes('malformed-inode32'),
    'tmpfs parser accepts absent or one bare inode32/inode64 mode and controls reject malformed, duplicate and conflicting forms');
  requireSource(controls.includes('p.mount = &m; if !checkpointObserverRouteTmpfsUnmountEligible(&m, &p)') &&
    controls.includes('mutate(&m, &p); if checkpointObserverRouteTmpfsUnmountEligible(&m, &p)') && controls.includes('wrong-proof-mount') &&
    controls.includes('opsProof.mount = &ops') && controls.includes('failedProof.mount = &failed') &&
    controls.includes('checkpointObserverRouteTmpfsUnmountEligible(&ops, &opsProof)') && controls.includes('checkpointObserverRouteTmpfsUnmountEligible(&failed, &failedProof)'),
    'each copied negative proves its bound positive before mutation and callback positives/errors carry fresh proofs bound to their actual mount copies');
  requireSource(cleanup.includes('if mountCleanup == nil {') && cleanup.includes('checkpointObserverRouteCheckHeldPaths(pins)') &&
    cleanup.includes('checkpointObserverRouteTmpfsCurrent(mountCleanup.mount)') && cleanup.includes('mountedSeen') && cleanup.includes('underlyingSeen') &&
    cleanup.indexOf('checkpointObserverRouteRequireExactNames(binDir, []string{"nodeagent.test"})') < cleanup.indexOf('os.Remove(file)') &&
    cleanup.indexOf('checkpointObserverRouteRequireOwnedFile(item.path, item.mode, item.gid, item.max)') < cleanup.indexOf('os.Remove(file)') &&
    cleanup.indexOf('os.Remove(file)') < cleanup.indexOf('checkpointObserverRouteRequireExactNames(binDir, []string{})') &&
    cleanup.indexOf('checkpointObserverRouteRequireExactNames(binDir, []string{})') < cleanup.indexOf('checkpointObserverRouteTmpfsSettleReferencesUsing(') &&
    cleanup.indexOf('checkpointObserverRouteTmpfsSettleReferencesUsing(') < cleanup.indexOf('checkpointObserverRouteTmpfsSettledProof(') &&
    cleanup.indexOf('checkpointObserverRouteTmpfsSettledProof(') < cleanup.indexOf('checkpointObserverRouteTmpfsUnmountUsing(') &&
    cleanup.indexOf('checkpointObserverRouteTmpfsUnmountUsing(') < cleanup.indexOf('checkpointObserverRouteRevealedUnderlyingBinCurrent(mountCleanup)') &&
    cleanup.indexOf('checkpointObserverRouteRevealedUnderlyingBinCurrent(mountCleanup)') < cleanup.indexOf('os.Remove(dir)') &&
    settle.indexOf('clientFD') < settle.indexOf('mountedRootFD') && settle.indexOf('mountedRootFD') < settle.indexOf('&mount.fd') &&
    settle.includes('checkpointObserverRouteTmpfsCloseReferenceUsing') && proof.includes('mount.heldRefs != 0') && proof.includes('mount.fd >= 0') &&
    proof.includes('os.ReadFile("/proc/self/mountinfo")') && proof.includes('unix.Statfs(cleanup.mount.path, &fs)') &&
    closeReference.indexOf('*descriptor = -1') < closeReference.indexOf('closeFD(owned)') &&
    cleanup.indexOf('checkpointObserverRouteTmpfsSettleReferencesUsing(') < cleanup.indexOf('checkpointObserverRouteTmpfsSettledProof(') &&
    cleanup.indexOf('checkpointObserverRouteTmpfsSettledProof(') < cleanup.indexOf('checkpointObserverRouteTmpfsUnmountUsing(') &&
    cleanupPropagatesUnmountError(cleanup) &&
    unmountUsing.includes('checkpointObserverRouteTmpfsUnmountEligible') && unmountUsing.includes('mount.unmountTry = true') && unmountUsing.includes('unmount(mount.path, 0)') &&
    'mounted cleanup preserves full legacy inventory and default branch, removes the exact known client, proves empty, unmounts once without force, and verifies revealed underlying custody before directory removal');
  const mutants = [
    ['host remount or fallback', mount.replace('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions())', 'unix.Mount("", "/run", "", unix.MS_REMOUNT|unix.MS_NOEXEC, "")')],
    ['missing exact root custody', mount.replace('unix.Fstat(rootFD, &heldRoot)', 'unix.Fstat(binFD, &heldRoot)')],
    ['real-size parser weakened', mountInfo.replace('superValues["size"] != "131072k"', 'false')],
    ['default root ownership weakened', mountInfo.replace('(seenSuper["uid"] && superValues["uid"] != "0")', 'false')],
    ['wrong mountpoint admitted', mountInfo.replace('fields[4] != target', 'false')],
    ['wrong held inode admitted', mount.replace('pathStat.Ino != mounted.Ino', 'false')],
    ['wrong filesystem mount admitted', mountInfo.replace('fields[separator+1] != "tmpfs"', 'false')],
    ['mount omitted', mount.replace('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions())', 'nil')],
    ['unexpected mounted bin topology', cleanup.replace('checkpointObserverRouteRequireExactNames(binDir, []string{"nodeagent.test"})', 'checkpointObserverRouteRequireExactNames(binDir, []string{})')],
    ['early unmount', cleanup.replace('checkpointObserverRouteTmpfsSettleReferencesUsing(mountCleanup.mount, mountCleanup.clientFD, mountCleanup.mountedRootFD, unix.Close)', 'checkpointObserverRouteTmpfsUnmountUsing(mountCleanup.mount, proof, unix.Unmount)')],
    ['forced unmount', unmountUsing.replace('unmount(mount.path, 0)', 'unmount(mount.path, unix.MNT_DETACH)')],
    ['children-clear omitted', pid1.replace('childrenClear: true', 'childrenClear: false')],
    ['reference close omitted', cleanup.replace('checkpointObserverRouteTmpfsSettleReferencesUsing(mountCleanup.mount, mountCleanup.clientFD, mountCleanup.mountedRootFD, unix.Close)', 'nil')],
    ['unmount error suppressed', cleanup.replace('if err := checkpointObserverRouteTmpfsUnmountUsing(mountCleanup.mount, proof, unix.Unmount); err != nil { return err }', 'checkpointObserverRouteTmpfsUnmountUsing(mountCleanup.mount, proof, unix.Unmount)')],
  ];
  for (const [label, mutant] of mutants) {
    requireSource(mutant !== ({ 'host remount or fallback': mount, 'missing exact root custody': mount, 'real-size parser weakened': mountInfo, 'default root ownership weakened': mountInfo, 'wrong mountpoint admitted': mountInfo, 'unexpected mounted bin topology': cleanup, 'early unmount': cleanup, 'forced unmount': unmountUsing, 'children-clear omitted': pid1, 'reference close omitted': cleanup })[label], `${label} mutant anchor is not unique`);
    let accepted = false;
    if (label.includes('root custody')) accepted = mutant.includes('unix.Fstat(rootFD, &heldRoot)');
    else if (label.includes('real-size')) accepted = mutant.includes('superValues["size"] != "131072k"');
    else if (label.includes('root ownership')) accepted = mutant.includes('(seenSuper["uid"] && superValues["uid"] != "0")');
    else if (label.includes('mountpoint')) accepted = mutant.includes('fields[4] != target');
    else if (label.includes('inode')) accepted = mutant.includes('pathStat.Ino != mounted.Ino');
    else if (label.includes('filesystem')) accepted = mutant.includes('fields[separator+1] != "tmpfs"');
    else if (label.includes('topology')) accepted = mutant.includes('checkpointObserverRouteRequireExactNames(binDir, []string{"nodeagent.test"})');
    else if (label.includes('early')) { const settleAt = mutant.indexOf('checkpointObserverRouteTmpfsSettleReferencesUsing('), unmountAt = mutant.indexOf('checkpointObserverRouteTmpfsUnmountUsing('); accepted = settleAt >= 0 && unmountAt >= 0 && settleAt < unmountAt; }
    else if (label.includes('forced')) accepted = mutant.includes('unmount(mount.path, 0)');
    else if (label.includes('children')) accepted = mutant.includes('childrenClear: true');
    else if (label.includes('reference close')) accepted = mutant.includes('checkpointObserverRouteTmpfsSettleReferencesUsing(');
    else if (label.includes('suppressed')) accepted = cleanupPropagatesUnmountError(mutant);
    else accepted = mutant.includes('unix.Mount("tmpfs", bin, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, checkpointObserverRouteTmpfsOptions())');
    requireSource(!accepted, `${label} source mutant was not rejected`);
  }
}

function assertDeclaredUnitInventory(sourceMap = sources, inventory = unitInventory) {
  const files = [
    'internal/checkpointgpuobserver/protocol_test.go', 'internal/checkpointgpuobserver/observer_linux_test.go',
    'internal/nodeagent/checkpoint_host_gpu_bridge_test.go', 'internal/nodeagent/checkpoint_host_gpu_bridge_linux_test.go', 'internal/nodeagent/checkpoint_managed_binding_linux_test.go',
    'internal/nodeagent/checkpoint_managed_binding_test.go', 'internal/nodeagent/checkpoint_local_observer_linux_test.go',
  ];
  for (const [pkg, expected] of Object.entries(inventory)) {
    const declaredSource = files.filter((file) => pkg.includes('checkpointgpuobserver') ? file.includes('checkpointgpuobserver/') : file.includes('nodeagent/'))
      .map((file) => sourceMap.get(file) ?? readFileSync(path.join(root, file), 'utf8')).join('\n');
    const declared = [...declaredSource.matchAll(/^func (Test\w+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
    const tops = [...new Set(expected.map((name) => name.split('/')[0]))];
    requireSource(tops.every((name) => declared.filter((item) => item === name).length === 1),
      `strict unit inventory for ${pkg} is absent or duplicated in source`);
  }
  const observerTest = sourceMap.get('internal/checkpointgpuobserver/observer_linux_test.go');
  const nodeBridgeTest = sourceMap.get('internal/nodeagent/checkpoint_host_gpu_bridge_linux_test.go');
  requireSource(inventory['./internal/checkpointgpuobserver'].includes('TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRoles'),
    'strict G2 inventory omits the actual successful-role ambiguity positive/negative top');
  requireSource(['single_match', 'disjoint_sibling', 'overlap_rejected', 'node_agent', 'fixed_supervisor', 'local_observer', 'absent', 'duplicate', 'wrong GPU']
    .every((name) => observerTest.includes(`"${name}"`)), 'observer role/worker subtest inventory is incomplete');
  requireSource(['namespace', 'peer PID', 'start ticks', 'boot ID', 'UID', 'executable'].every((name) => nodeBridgeTest.includes(`"${name}"`)),
    'signed host peer mutation subtest inventory is incomplete');
}

function inventoryCoverageControls() {
  assertDeclaredUnitInventory(sources);
  const missingRequiredTop = new Map(Object.entries(unitInventory));
  missingRequiredTop.set('./internal/checkpointgpuobserver', unitInventory['./internal/checkpointgpuobserver'].filter((name) => name !== 'TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRoles'));
  let missingTopFailure;
  try { assertDeclaredUnitInventory(sources, Object.fromEntries(missingRequiredTop)); } catch (error) { missingTopFailure = error; }
  requireSource(missingTopFailure instanceof Error && missingTopFailure.message === 'checkpoint observer route source contract failed: strict G2 inventory omits the actual successful-role ambiguity positive/negative top',
    `actual successful-role ambiguity inventory omission missed its intended guard (${missingTopFailure instanceof Error ? missingTopFailure.message : 'accepted'})`);
  const pathName = 'internal/checkpointgpuobserver/observer_linux_test.go';
  const original = sources.get(pathName);
  const marker = 'func TestHostNSpidParserRetainsRepeatedIDsAcrossNamespaceLevels(t *testing.T) {';
  requireSource(original.split(marker).length === 2, 'retained repeated-NSpid top-level source anchor is not unique');
  const mutated = new Map(sources);
  mutated.set(pathName, original.replace(marker, 'func TestHostNSpidParserRetainedTopRemoved(t *testing.T) {'));
  let failure;
  try { assertDeclaredUnitInventory(mutated); } catch (error) { failure = error; }
  requireSource(failure instanceof Error && failure.message === 'checkpoint observer route source contract failed: strict unit inventory for ./internal/checkpointgpuobserver is absent or duplicated in source',
    `missing retained original top mutant missed the inventory guard (${failure instanceof Error ? failure.message : 'accepted'})`);
}

function assertFixedTransports(verifier, verifyMutants = true) {
  const inputBoundary = verifier.indexOf('\nconst allowedModes');
  requireSource(inputBoundary > 0, 'fixed toolchain input boundary is missing');
  const fixedInputs = verifier.slice(0, inputBoundary);
  const unitStart = verifier.indexOf('\nfunction runUnit() {');
  const unitEnd = verifier.indexOf('\nconst routeProxmoxReceiver', unitStart);
  const principalStart = verifier.indexOf('\nfunction verifyWslUnitPrincipal() {');
  const principalEnd = verifier.indexOf('\nfunction runUnit()', principalStart);
  const kernelStart = verifier.indexOf('\nfunction runKernel() {');
  const kernelEnd = verifier.indexOf('\nif (mode ===', kernelStart);
  const compileStart = verifier.indexOf('\nfunction compileLinuxTest(');
  const compileEnd = verifier.indexOf('\nfunction runUnit()', compileStart);
  const receiverStart = verifier.indexOf('\nconst routeProxmoxReceiver = String.raw`');
  const receiverEnd = verifier.indexOf('\nfunction shellQuote(', receiverStart);
  requireSource(unitStart >= 0 && unitEnd > unitStart && kernelStart >= 0 && kernelEnd > kernelStart &&
    compileStart >= 0 && compileEnd > compileStart && receiverStart >= 0 && receiverEnd > receiverStart,
    'fixed unit/kernel transport source regions are not uniquely bounded');
  const unit = verifier.slice(unitStart, unitEnd);
  const principalCheck = verifier.slice(principalStart, principalEnd);
  const pathMapStart = verifier.indexOf('\nfunction windowsPathToWsl(');
  const pathMapEnd = verifier.indexOf('\nfunction verifyWslUnitPrincipal()', pathMapStart);
  const pathMap = verifier.slice(pathMapStart, pathMapEnd);
  const kernel = verifier.slice(kernelStart, kernelEnd);
  const compile = verifier.slice(compileStart, compileEnd);
  const createCompilerStart = verifier.indexOf('\nfunction createCompilerTrees(');
  const createCompilerEnd = verifier.indexOf('\nfunction verifyCompilerTree(', createCompilerStart);
  const compilerCreate = verifier.slice(createCompilerStart, createCompilerEnd);
  const captureTreeStart = verifier.indexOf('\nfunction captureCompilerTree(');
  const captureTreeEnd = verifier.indexOf('\nfunction createCompilerTrees(', captureTreeStart);
  const compilerCapture = verifier.slice(captureTreeStart, captureTreeEnd);
  const verifyRootsStart = verifier.indexOf('\nfunction verifyCompilerRoots(');
  const verifyRootsEnd = verifier.indexOf('\nfunction verifyCompilerTree(', verifyRootsStart);
  const compilerRootCheck = verifier.slice(verifyRootsStart, verifyRootsEnd);
  const diagnosticStart = verifier.indexOf('\nfunction boundedCompilerDiagnostic(');
  const diagnosticEnd = verifier.indexOf('\nfunction fixedFile(', diagnosticStart);
  const diagnostic = verifier.slice(diagnosticStart, diagnosticEnd);
  const receiverDiagnosticStart = verifier.indexOf('\nfunction boundedReceiverDiagnostic(');
  const receiverDiagnosticEnd = verifier.indexOf('\nfunction receiverDiagnosticControls(', receiverDiagnosticStart);
  const receiverDiagnostic = verifier.slice(receiverDiagnosticStart, receiverDiagnosticEnd);
  const invokeStart = verifier.indexOf('\nfunction invoke(');
  const invokeEnd = verifier.indexOf('\nfunction boundedCompilerDiagnostic(', invokeStart);
  const invokeSource = verifier.slice(invokeStart, invokeEnd);
  const receiver = verifier.slice(receiverStart, receiverEnd);
  const replaceRegionOnce = (text, startMarker, endMarker, before, after) => {
    const start = text.indexOf(startMarker);
    const end = text.indexOf(endMarker, start);
    requireSource(start >= 0 && end > start, `mutant region ${startMarker} is not uniquely bounded`);
    const region = text.slice(start, end);
    requireSource(region.split(before).length === 2, `mutant anchor is not unique within ${startMarker}`);
    return text.slice(0, start) + region.replace(before, after) + text.slice(end);
  };
  requireSource(fixedInputs.includes("const fixedGoBin = 'C:/Users/Sasha/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin'") &&
    fixedInputs.includes("const fixedSSH = 'C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe'") &&
    fixedInputs.includes("const fixedIdentity = 'C:/Users/Sasha/.ssh/cmp170_proxmox'") && fixedInputs.includes("const fixedKnownHosts = 'C:/Users/Sasha/.ssh/known_hosts'"),
    'fixed cached compiler, SSH, identity and known-hosts paths are absent');
  requireSource(compile.includes("GOOS: 'linux'") && compile.includes("GOARCH: 'amd64'") && compile.includes("GOAMD64: 'v1'") &&
    compile.includes("CGO_ENABLED: '0'") && compile.includes("GOTOOLCHAIN: 'local'") && compile.includes("GOENV: 'off'") && compile.includes("GOFLAGS: ''"),
    'fixed Linux cross-compile environment is incomplete or ambient toolchain selection is allowed');
  requireSource(compile.includes('PATH: `${fixedGoBin};C:/Windows/System32`') && compile.includes('GOCACHE: path.join(scratch, \'go-cache\')') &&
    compile.includes('GOTMPDIR: path.join(scratch, \'go-tmp\')') && compile.includes("GOMODCACHE: 'C:/Users/Sasha/go/pkg/mod'") &&
    compile.includes("GOPROXY: 'off'") && compile.includes("GOSUMDB: 'off'") && !compile.includes('...process.env'),
    'compiler cache/temp/module paths are pinned inside private scratch or fixed module cache, and module transport is disabled');
  requireSource(verifier.includes('function captureCompilerTree(directory, originalRoot = null)') && verifier.includes('function verifyCompilerTree(directory, pin)') &&
    verifier.includes('function removeCompilerTree(directory, pin)') && verifier.includes('2 * 1024 * 1024 * 1024') && verifier.includes('entries.length > 200000') &&
    unit.includes("for (const name of ['go-cache', 'go-tmp']) pins.set(name, captureCompilerTree(path.join(scratch, name), pins.get(name)))") &&
    kernel.includes("for (const name of ['go-cache', 'go-tmp']) pins.set(name, captureCompilerTree(path.join(scratch, name), pins.get(name)))"),
    'compiler cache/temp trees are fully enumerated under explicit byte/entry bounds and removed only after identity recheck');
  requireSource(compilerCreate.includes('mkdirSync(directory, { mode: 0o700 })') && !compilerCreate.includes('recursive: true') &&
    compilerCreate.includes('root.dev !== rootPin.dev || root.ino !== rootPin.ino') &&
    compilerCreate.indexOf('pins.set(name, ownerPin)') >= 0 && compilerCreate.indexOf('pins.set(name, ownerPin)') < compilerCreate.indexOf('captureCompilerTree(directory, ownerPin)') &&
    compilerCreate.includes('captured.entries.length !== 0 || captured.totalBytes !== 0') &&
    unit.indexOf('createCompilerTrees(scratch, rootPin, pins);') >= 0 && unit.indexOf('createCompilerTrees(scratch, rootPin, pins);') < unit.indexOf('compileLinuxTest(') &&
    kernel.indexOf('createCompilerTrees(scratch, rootPin, pins);') >= 0 && kernel.indexOf('createCompilerTrees(scratch, rootPin, pins);') < kernel.indexOf('compileLinuxTest(') &&
    compilerRootCheck.includes('function verifyCompilerRoots(scratch, pins)') && compilerRootCheck.includes('info.dev !== pin.dev || info.ino !== pin.ino || info.mode !== pin.mode') &&
    unit.indexOf('for (const [index, [pkg, expected]]') < unit.indexOf('verifyCompilerRoots(scratch, pins);') && unit.indexOf('verifyCompilerRoots(scratch, pins);') < unit.indexOf('compileLinuxTest(') &&
    kernel.indexOf('verifyCompilerRoots(scratch, pins);') < kernel.indexOf('compileLinuxTest(') &&
    kernel.indexOf('verifyCompilerRoots(scratch, pins);', kernel.indexOf('verifyCompilerRoots(scratch, pins);') + 1) > kernel.indexOf('compileLinuxTest(') &&
    kernel.indexOf('verifyCompilerRoots(scratch, pins);', kernel.indexOf('verifyCompilerRoots(scratch, pins);') + 1) < kernel.lastIndexOf('compileLinuxTest(') &&
    compilerCapture.includes('captureCompilerTree(directory, originalRoot = null)') && compilerCapture.includes('rootInfo.dev !== originalRoot.dev || rootInfo.ino !== originalRoot.ino || rootInfo.mode !== originalRoot.mode'),
    'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture');
  requireSource(compile.includes('diagnosticLimit: 4096') && invokeSource.includes('boundedCompilerDiagnostic(result, options.diagnosticLimit)') &&
    diagnostic.includes(".replace(/[A-Za-z]:\\\\Users\\\\[^\\\\\\r\\n]+/gi, '<user-home>')") && diagnostic.includes('output.slice(-limit)') &&
    diagnostic.includes('user-home redacted'),
    'compiler failure diagnostics must be compiler-only, bounded to four KiB, and redact the user-home path');
  requireSource(invokeSource.includes('failed && options.receiverDiagnostic ? boundedReceiverDiagnostic(result)') &&
    invokeSource.includes('options.receiverDiagnostic && options.diagnosticLimit') &&
    kernel.includes('receiverDiagnostic: true') && !kernel.includes('diagnosticLimit:') &&
    kernel.split('receiverDiagnostic: true').length === 2,
    'fixed-PVE failure diagnostics must use only the explicit receiver parser and remain disjoint from compiler-tail diagnostics');
  requireSource(receiverDiagnostic.includes('Buffer.byteLength(output, \'utf8\') > 3 * 1024 * 1024') &&
    receiverDiagnostic.includes('records.length > 18') && receiverDiagnostic.includes('line.length > 128') &&
    receiverDiagnostic.includes('receiverFailureStages.has(stageMatch[1])') && receiverDiagnostic.includes('locations.length >= 16') &&
    receiverDiagnostic.includes('lineNumber > 4800') && receiverDiagnostic.includes('stage !== \'test_nonzero\'') &&
    receiverDiagnostic.includes('REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test\\.go:'),
    'receiver parser must accept only bounded fixed stages and exact source-location records');
  const exceptionWalkStart = receiver.indexOf('\ndef embedded_exception_line(error):');
  const exceptionWalkEnd = receiver.indexOf('\ndef initial_namespace()', exceptionWalkStart);
  const exceptionClassStart = receiver.indexOf('SAFE_EXCEPTION_CLASSES = {');
  const exceptionClassEnd = receiver.indexOf('\ndef fail(', exceptionClassStart);
  const exceptionClassMap = receiver.slice(exceptionClassStart, exceptionClassEnd).trimEnd();
  const expectedExceptionClassMap = `SAFE_EXCEPTION_CLASSES = {
    AssertionError: "AssertionError", AttributeError: "AttributeError", IndexError: "IndexError",
    KeyError: "KeyError", MemoryError: "MemoryError", OSError: "OSError", OverflowError: "OverflowError",
    RuntimeError: "RuntimeError", TimeoutError: "TimeoutError", TypeError: "TypeError",
    UnicodeError: "UnicodeError", ValueError: "ValueError",
}`;
  const exceptionHandlerStart = receiver.lastIndexOf('\ntry:\n    main()');
  const exceptionWalk = receiver.slice(exceptionWalkStart, exceptionWalkEnd);
  const exceptionHandler = receiver.slice(exceptionHandlerStart);
  requireSource(exceptionClassStart >= 0 && exceptionClassEnd > exceptionClassStart && exceptionClassMap === expectedExceptionClassMap,
    'receiver internal exception class inventory must remain the exact finite builtin identity map');
  requireSource(exceptionWalkStart >= 0 && exceptionWalkEnd > exceptionWalkStart && exceptionHandlerStart > exceptionWalkEnd &&
    exceptionWalk.includes('SAFE_EXCEPTION_CLASSES.get(type(error), "unavailable")') &&
    exceptionWalk.includes('frame.f_code.co_filename == "<string>"') &&
    exceptionWalk.includes('walked < 16') && !exceptionWalk.includes('walked < 160') && exceptionWalk.includes('1 <= line_number <= 1000') &&
    exceptionWalk.includes('REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\\n') &&
    exceptionWalk.includes('REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=%s line=%s\\n') &&
    !exceptionWalk.includes('str(error)') && !exceptionWalk.includes('repr(error)') && !exceptionWalk.includes('type(error).__name__') &&
    exceptionHandler.includes('except Exception as error:\n    fail_exception(error)') &&
    !exceptionHandler.includes('except BaseException as error:'),
    'receiver internal exception boundary must emit only fixed class identities and one bounded <string> line while leaving SystemExit untouched');
  requireSource(receiverDiagnostic.includes('exceptionMatch[1]') && receiverDiagnostic.includes('exceptionMatch[2]') &&
    receiverDiagnostic.includes('stage !== \'receiver_exception\'') && receiverDiagnostic.includes('stage === \'receiver_exception\' && !exception') &&
    verifier.includes('receiverExceptionDiagnosticControls();'),
    'receiver exception parser must require one exact bounded exception record only for the fixed exception stage');
  requireSource(receiverDiagnostic.includes('const exceptionMatch = /^REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=(AssertionError|AttributeError|IndexError|KeyError|MemoryError|OSError|OverflowError|RuntimeError|TimeoutError|TypeError|UnicodeError|ValueError|unavailable) line=(unavailable|[1-9][0-9]{0,2}|1000)$/'),
    'receiver exception parser class and line vocabulary must remain finite and canonical');
  requireSource(unit.includes("process.platform !== 'win32'") && unit.includes('compileLinuxTest(fixedGo') &&
    unit.includes("'-u', 'berd'") && unit.includes("'/usr/bin/env', '-i'") && unit.includes("'-test.count=1'") &&
    unit.includes('parseVerboseInventory(output, expected') && unit.includes('removeExactScratch(scratch, rootPin, pins)'),
    'unit suite does not use the fixed Windows-to-WSL transport, literal berd principal, strict inventory and exact cleanup');
  requireSource(principalStart >= 0 && principalEnd > principalStart &&
    principalCheck.includes("invoke('wsl.exe', ['-d', 'Ubuntu', '-u', 'berd', '--exec', '/usr/bin/id', '-u']") &&
    principalCheck.includes("if (output.trim() !== '1000')"),
    'WSL principal validator must run fixed /usr/bin/id -u as berd and require exact UID 1000');
  requireSource(unit.indexOf('verifyWslUnitPrincipal();') >= 0 && unit.indexOf('verifyWslUnitPrincipal();') < unit.indexOf('mkdtempSync('),
    'WSL principal UID check must be consumed before private compiler setup');
  requireSource(pathMap.includes("'-u', 'root', '--exec', 'wslpath'") &&
    unit.includes("'-u', 'root', '--exec', 'chmod'") &&
    !unit.includes("'-u', '1000'") && !unit.includes("'-u', 'root', '--exec', '/usr/bin/env'"),
    'WSL root use must remain limited to fixed path conversion and chmod; test launch must not fall back to root');
  requireSource(kernel.includes("process.platform !== 'win32'") && kernel.includes('compileLinuxTest(fixedGo') &&
    kernel.includes("'checkpoint_container_kernel'") && kernel.includes("'checkpoint_local_observer_kernel'") &&
    kernel.includes("'-oStrictHostKeyChecking=yes'") && kernel.includes('`-oUserKnownHostsFile=${fixedKnownHosts}`') &&
    kernel.includes("'-oProxyJump=none'") && kernel.includes("'-oProxyCommand=none'") &&
    kernel.includes("'-oHostName=10.0.0.3'") && kernel.includes("'root@10.0.0.3'") &&
    kernel.includes('Buffer.concat([hostBytes, nodeBytes])') && kernel.includes('removeExactScratch(scratch, rootPin, pins)'),
    'kernel route does not use both fixed cross-compiled images, strict direct PVE SSH transport and held local cleanup');
  requireSource(receiver.includes('import ctypes, hashlib, os, re, selectors, signal, stat, subprocess, sys, tempfile, time') &&
    receiver.includes('re.fullmatch(r"=== RUN\\s+(\\S+)", record)') &&
    receiver.includes('re.match(r"--- (?:PASS|SKIP|FAIL)(?:\\s|:)", record)') &&
    receiver.includes('EXPECTED_PIDNS = 4026531836') && receiver.includes('os.pidfd_open(proc.pid, 0)') &&
    receiver.includes('signal.pidfd_send_signal(pidfd, signal.SIGTERM)') && receiver.includes('signal.pidfd_send_signal(pidfd, signal.SIGKILL)') &&
    receiver.includes('preexec_fn=set_receiver_parent_death') && receiver.includes('os.getppid() != receiver_pid') &&
    receiver.includes('MAX_OUTPUT = 2 * 1024 * 1024') && receiver.includes('MAX_SECONDS = 125') &&
    receiver.includes('os.O_RDWR | os.O_CREAT | os.O_EXCL') &&
    receiver.includes('exact_cleanup(ROOT, tmp_fd, held_tmp, upload_fd, held_root, files)') &&
    receiver.includes('REMOTE_OBSERVER_ROUTE_UPLOAD_CLEANUP_PASS') &&
    receiver.includes('os.listdir(upload_fd)') && receiver.includes('if os.listdir(upload_fd):\n        fail("cleanup_file_absence")'),
    'fixed PVE receiver lacks bounded initial-namespace/process identity, pidfd cleanup, readable upload verification, output bounds or exact cleanup');
  requireSource(receiver.includes('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS') && receiver.includes('CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS'),
    'fixed receiver does not require composed parent-death/reap and outside-sentinel success evidence');
  const handoffStart = receiver.indexOf('\ndef handoff_exec_uploads(');
  const handoffEnd = receiver.indexOf('\ndef exact_cleanup', handoffStart);
  const handoff = receiver.slice(handoffStart, handoffEnd);
  const handoffCall = 'handoff_exec_uploads(specs, files, ROOT, tmp_fd, held_tmp, upload_fd, held_root)';
  const handoffCallAt = receiver.indexOf(handoffCall);
  const spawnAt = receiver.indexOf('proc = subprocess.Popen(');
  const recheckedNameAt = handoff.lastIndexOf('if pin_upload(fd, name, expected_size, expected_sha) != pin:');
  const finalRootCheckAt = handoff.lastIndexOf('verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)');
  const rootCheckStart = receiver.indexOf('\ndef verify_upload_root(');
  const rootCheckEnd = receiver.indexOf('\ndef handoff_exec_uploads(', rootCheckStart);
  const rootCheck = receiver.slice(rootCheckStart, rootCheckEnd);
  const outerFailureStart = receiver.lastIndexOf('    except BaseException as failure:');
  const outerFailure = receiver.slice(outerFailureStart);
  const adoptedAt = handoff.indexOf('files[name] = (read_fd, read_pin)');
  const writerCloseAt = handoff.indexOf('os.close(writer_fd)');
  requireSource(handoffStart >= 0 && handoffEnd > handoffStart &&
    rootCheckStart >= 0 && rootCheckEnd > rootCheckStart &&
    rootCheck.includes('(root_now.st_dev, root_now.st_ino) != held_root[:2]') &&
    rootCheck.includes('(root_named.st_dev, root_named.st_ino) != held_root[:2]') &&
    rootCheck.includes('(tmp_now.st_dev, tmp_now.st_ino) != held_tmp[:2]') &&
    receiver.includes('specs = [("checkpoint-observer-host.test", int(sys.argv[1]), sys.argv[2]), ("nodeagent.test", int(sys.argv[3]), sys.argv[4])]') &&
    (handoff.match(/for name, expected_size, expected_sha in specs:/g) || []).length === 2 &&
    handoff.includes('pin_upload(writer_fd, name, expected_size, expected_sha)') &&
    handoff.includes('os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=upload_fd)') &&
    handoff.includes('pin_upload(read_fd, name, expected_size, expected_sha)') &&
    handoff.includes('read_pin != original_pin') &&
    handoff.includes('(writer.st_dev, writer.st_ino, writer.st_size) != (reader.st_dev, reader.st_ino, reader.st_size)') &&
    adoptedAt >= 0 && adoptedAt < handoff.indexOf('adopted = True') && handoff.indexOf('adopted = True') < writerCloseAt &&
    handoff.includes('if read_fd is not None and not adopted:') && handoff.includes('os.close(read_fd)') &&
    handoff.includes('verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)') &&
    finalRootCheckAt > recheckedNameAt &&
    handoffCallAt >= 0 && spawnAt > handoffCallAt && receiver.indexOf(handoffCall) === receiver.lastIndexOf(handoffCall) &&
    receiver.includes('close_fds=True') && !receiver.includes('pass_fds=') &&
    outerFailure.includes('cleanup_errors = []') && outerFailure.includes('receiver failure descriptor cleanup was uncertain') &&
    outerFailure.includes('for fd, _ in files.values():\n            try:\n                os.close(fd)\n            except BaseException as error:\n                cleanup_errors.append(error)') &&
    !outerFailure.includes('except OSError:\n                pass'),
    'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn');
  const failureStart = receiver.indexOf('if status != 0:');
  const failureEnd = receiver.indexOf('\n        events =', failureStart);
  const failedChildBlock = receiver.slice(failureStart, failureEnd);
  const nestedReceiverStart = receiver.indexOf('def failure_nested_diagnostic(text, *, reject=fail):');
  const nestedReceiverEnd = receiver.indexOf('\ndef failure_nested_diagnostic_controls():', nestedReceiverStart);
  const nestedReceiver = receiver.slice(nestedReceiverStart, nestedReceiverEnd);
  requireSource(receiver.includes('def failure_source_locations(text):') &&
    nestedReceiver.includes('def failure_nested_diagnostic(text, *, reject=fail):') && nestedReceiver.includes('wrapped_prefix = "        " + prefix') &&
    nestedReceiver.includes('for line in text.splitlines():') && nestedReceiver.includes('"REMOTE_OBSERVER_ROUTE_NESTED" not in line') &&
    nestedReceiver.includes('if not line.startswith(wrapped_prefix):\n            reject("malformed_result_record")') &&
    nestedReceiver.includes('if len(records) != 1:\n        reject("malformed_result_record")') &&
    nestedReceiver.includes('full_record = prefix + records[0]') && nestedReceiver.includes('len(full_record.encode("ascii")) > 128') &&
    !nestedReceiver.includes('fail("malformed_result_record")') && !nestedReceiver.includes('line.lstrip()') &&
    receiver.includes('fail("test_nonzero", failure_source_locations(text), failure_nested_diagnostic(text))') &&
    receiver.includes('if len(records) != 1:') && receiver.includes('int(exit_value[5:]) > 255') && receiver.includes('int(exit_value[7:]) > 64') &&
    receiver.includes('stage=test_nonzero exit=') && receiver.includes('overflow=(yes|no) assertions=') &&
    nestedReceiver.includes('if overflow == "yes" and (client is not None or broker is not None): reject("malformed_result_record")') &&
    nestedReceiver.includes('if broker is not None and client is None: reject("malformed_result_record")') &&
    receiver.includes('REMOTE_OBSERVER_ROUTE_NESTED %s\\n') &&
    receiver.includes('line_number = int(match.group(1))') && receiver.includes('line_number > 4800 or line_number in seen') &&
    receiver.includes('if len(locations) == 16:') && receiver.includes('source_locations[:16]') &&
    receiver.includes('REMOTE_OBSERVER_ROUTE_FAILURE stage=%s\\n') &&
    receiver.includes('REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:%d\\n') &&
    failedChildBlock.includes('fail("test_nonzero", failure_source_locations(text), failure_nested_diagnostic(text))') &&
    !failedChildBlock.includes('sys.stdout.write') && !failedChildBlock.includes('sys.stderr.write(text)'),
    'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations');
  const nestedControlsStart = receiver.indexOf('\ndef failure_nested_diagnostic_controls():');
  const nestedControlsEnd = receiver.indexOf('\ndef embedded_exception_line(', nestedControlsStart);
  const nestedControls = receiver.slice(nestedControlsStart, nestedControlsEnd);
  const receiverMainStart = receiver.indexOf('\ndef main():');
  const receiverMain = receiver.slice(receiverMainStart);
  requireSource(nestedControlsStart === nestedReceiverEnd && nestedControlsEnd > nestedControlsStart &&
    nestedControls.includes('expected = failure_nested_diagnostic(raw_positive)') &&
    nestedControls.includes('failure_nested_diagnostic(raw, reject=_reject)') &&
    nestedControls.includes('except _ExpectedNestedDiagnosticReject as error:') &&
    nestedControls.includes('if error is not reject_sentinel:') &&
    !nestedControls.includes('except BaseException') &&
    nestedControls.includes('failure_nested_diagnostic(blank) is not None') &&
    nestedControls.includes('len((prefix + tail_signal64).encode("ascii")) != 127') &&
    nestedControls.includes('len((prefix + tail_k123).encode("ascii")) != 123') &&
    nestedControls.includes('len((prefix + tail129).encode("ascii")) != 129') &&
    nestedControls.includes('for raw in malformed:\n        expect_reject(transcript(raw))') &&
    nestedControls.includes('replace("signal:64", "code:256")') &&
    nestedControls.includes('replace("4799,4798,1988,1346", "4801,4798,1988,1346")') &&
    nestedControls.includes('replace("B38", "B39")') &&
    nestedControls.includes('replace("overflow=no", "overflow=yes")') &&
    !nestedControls.includes('exec(') && !nestedControls.includes('eval(') &&
    !nestedControls.includes('sys.stderr') && !nestedControls.includes('global ') &&
    receiverMain.includes('def main():\n    global ROOT, upload_fd\n    failure_nested_diagnostic_controls()\n    initial_namespace()'),
    'actual Python raw nested parser controls must run pre-effect with default positive and dedicated rejection callback');
  pythonNestedHopControls(nestedReceiver);
  const nodeNestedReceiver = verifier.slice(verifier.indexOf('\nfunction boundedReceiverDiagnostic('), verifier.indexOf('\nfunction receiverDiagnosticControls('));
  requireSource(nodeNestedReceiver.includes('stage=test_nonzero exit=') && nodeNestedReceiver.includes('overflow=(yes|no) assertions=') &&
    nodeNestedReceiver.includes("nestedMatch[2] === 'yes' && (nestedMatch[4] !== undefined || nestedMatch[5] !== undefined)") &&
    nodeNestedReceiver.includes('nestedMatch[5] !== undefined && nestedMatch[4] === undefined') &&
    nodeNestedReceiver.includes("nestedMatch[6] !== undefined && (nestedMatch[2] !== 'no' || nestedMatch[4] === undefined || nestedMatch[5] !== 'B15'") &&
    nodeNestedReceiver.includes('assertions.includes(1988)') && nodeNestedReceiver.includes('assertions.includes(1346)'),
  'Node receiver independently validates original nested fields, overflow, and finite client/broker association');
  if (!verifyMutants) return;
  receiverDiagnosticControls();
  receiverExceptionDiagnosticControls();
  nestedDiagnosticControls();
  const receiverPredicates = [
    ['Python Go-testing wrapper indentation removed', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'wrapped_prefix = "        " + prefix', 'wrapped_prefix = prefix', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python unknown nested framing accepted', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if not line.startswith(wrapped_prefix):\n            reject("malformed_result_record")', 'if False:\n            reject("malformed_result_record")', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python complete-record byte cap weakened to tail-only', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'len(full_record.encode("ascii")) > 128', 'len(records[0].encode("ascii")) > 128', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python nested malformed branch bypasses rejection callback', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if not line.startswith(wrapped_prefix):\n            reject("malformed_result_record")', 'if not line.startswith(wrapped_prefix):\n            fail("malformed_result_record")', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python pure-control negative bypasses private callback', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'failure_nested_diagnostic(raw, reject=_reject)', 'failure_nested_diagnostic(raw)', 'actual Python raw nested parser controls must run pre-effect with default positive and dedicated rejection callback'],
    ['Python parser preflight moved after namespace effects', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'failure_nested_diagnostic_controls()\n    initial_namespace()', 'initial_namespace()\n    failure_nested_diagnostic_controls()', 'actual Python raw nested parser controls must run pre-effect with default positive and dedicated rejection callback'],
    ['Python parser private callback signature removed', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'def failure_nested_diagnostic(text, *, reject=fail):', 'def failure_nested_diagnostic(text):', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python overflow evidence guard removed', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if overflow == "yes" and (client is not None or broker is not None): reject("malformed_result_record")', 'if False: reject("malformed_result_record")', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python broker association guard removed', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if broker is not None and client is None: reject("malformed_result_record")', 'if False: reject("malformed_result_record")', 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['Python optional-K association guard removed', '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if phase is not None and (overflow != "no" or client is None or broker != "B15"', 'if False: reject("malformed_result_record")', 'Python optional-K phase must bind only to the actual bounded B15 client and original producer sites'],
    ['Node overflow evidence guard removed', '\nfunction boundedReceiverDiagnostic(', '\nfunction receiverDiagnosticControls(', "if (nestedMatch[2] === 'yes' && (nestedMatch[4] !== undefined || nestedMatch[5] !== undefined)) return '';", "if (false) return '';", 'Node receiver independently validates original nested fields, overflow, and finite client/broker association'],
    ['Node broker association guard removed', '\nfunction boundedReceiverDiagnostic(', '\nfunction receiverDiagnosticControls(', "if (nestedMatch[5] !== undefined && nestedMatch[4] === undefined) return '';", "if (false) return '';", 'Node receiver independently validates original nested fields, overflow, and finite client/broker association'],
    ['Node optional-K association guard removed', '\nfunction boundedReceiverDiagnostic(', '\nfunction receiverDiagnosticControls(', "if (nestedMatch[6] !== undefined && (nestedMatch[2] !== 'no' || nestedMatch[4] === undefined || nestedMatch[5] !== 'B15'", "if (false) return '';", 'Node receiver independently validates original nested fields, overflow, and finite client/broker association'],
  ];
  for (const [label, start, end, before, after, expectedFailure] of receiverPredicates) {
    const mutant = replaceRegionOnce(verifier, start, end, before, after);
    let failure;
    try { assertFixedTransports(mutant, false); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${expectedFailure}`,
      `${label} mutant missed its intended receiver guard (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
  const fixedGoAnchor = "const fixedGoBin = 'C:/Users/Sasha/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.23.4.windows-amd64/bin'";
  requireSource(fixedInputs.split(fixedGoAnchor).length === 2, 'fixed Go path mutation anchor is not unique inside the fixed-input boundary');
  const mutants = [
    ['fixed Go toolchain path changed', verifier.replace(fixedGoAnchor, "const fixedGoBin = 'C:/other/bin'"), 'fixed cached compiler, SSH, identity and known-hosts paths are absent'],
    ['module transport enabled', replaceRegionOnce(verifier, '\nfunction compileLinuxTest(', '\nfunction runUnit()', "GOPROXY: 'off'", "GOPROXY: 'https://proxy.golang.org'"), 'compiler cache/temp/module paths are pinned inside private scratch or fixed module cache, and module transport is disabled'],
    ['unit compiler roots not initialized before compile', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', 'createCompilerTrees(scratch, rootPin, pins);', 'void 0;'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['kernel compiler roots not initialized before compile', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', 'createCompilerTrees(scratch, rootPin, pins);', 'void 0;'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['unit compile root recheck omitted', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', 'verifyCompilerRoots(scratch, pins);', 'void 0;'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['first kernel compile root recheck omitted', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', 'verifyCompilerRoots(scratch, pins);\n    pins.set(path.basename(hostPath)', 'pins.set(path.basename(hostPath)'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['second kernel compile root recheck omitted', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', 'verifyCompilerRoots(scratch, pins);\n    pins.set(path.basename(nodePath)', 'pins.set(path.basename(nodePath)'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['compiler root creation became recursive', replaceRegionOnce(verifier, '\nfunction createCompilerTrees(', '\nfunction verifyCompilerTree(', 'mkdirSync(directory, { mode: 0o700 })', 'mkdirSync(directory, { mode: 0o700, recursive: true })'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['compiler root identity recheck weakened', replaceRegionOnce(verifier, '\nfunction verifyCompilerRoots(', '\nfunction verifyCompilerTree(', 'info.dev !== pin.dev || info.ino !== pin.ino || info.mode !== pin.mode', 'false'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['final compiler creation identity recheck weakened', replaceRegionOnce(verifier, '\nfunction captureCompilerTree(', '\nfunction createCompilerTrees(', 'rootInfo.dev !== originalRoot.dev || rootInfo.ino !== originalRoot.ino || rootInfo.mode !== originalRoot.mode', 'rootInfo.dev !== originalRoot.dev'), 'compiler cache/temp roots must be exclusive, immediately registered, empty at creation, and rechecked before both compiles and final capture'],
    ['final compiler tree capture lost creation identity', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', 'captureCompilerTree(path.join(scratch, name), pins.get(name))', 'captureCompilerTree(path.join(scratch, name))'), 'compiler cache/temp trees are fully enumerated under explicit byte/entry bounds and removed only after identity recheck'],
    ['compiler diagnostic bound removed', replaceRegionOnce(verifier, '\nfunction compileLinuxTest(', '\nfunction runUnit()', 'diagnosticLimit: 4096', 'diagnosticLimit: 0'), 'compiler failure diagnostics must be compiler-only, bounded to four KiB, and redact the user-home path'],
    ['compiler diagnostic user-home redaction removed', replaceRegionOnce(verifier, '\nfunction boundedCompilerDiagnostic(', '\nfunction fixedFile(', ".replace(/[A-Za-z]:\\\\Users\\\\[^\\\\\\r\\n]+/gi, '<user-home>')", ".replace(/$^/, '<user-home>')"), 'compiler failure diagnostics must be compiler-only, bounded to four KiB, and redact the user-home path'],
    ['receiver diagnostic mode replaced by compiler tail', replaceRegionOnce(verifier, '\nfunction invoke(', '\nfunction boundedCompilerDiagnostic(', 'options.receiverDiagnostic ? boundedReceiverDiagnostic(result)', "options.diagnosticLimit ? boundedCompilerDiagnostic(result, options.diagnosticLimit) : ''"), 'fixed-PVE failure diagnostics must use only the explicit receiver parser and remain disjoint from compiler-tail diagnostics'],
    ['receiver diagnostic option omitted', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', 'receiverDiagnostic: true', 'receiverDiagnostic: false'), 'fixed-PVE failure diagnostics must use only the explicit receiver parser and remain disjoint from compiler-tail diagnostics'],
    ['receiver child output emitted raw', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'fail("test_nonzero", failure_source_locations(text), failure_nested_diagnostic(text))', 'sys.stderr.write(text)\n            fail("test_nonzero")'), 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['receiver source-location cap widened', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if len(locations) == 16:', 'if len(locations) == 160:'), 'receiver nonzero path must emit only its fixed stage marker and at most sixteen sanitized source locations'],
    ['receiver executable handoff omitted', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', '        handoff_exec_uploads(specs, files, ROOT, tmp_fd, held_tmp, upload_fd, held_root)\n', ''), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver executable descriptor left writable', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=upload_fd', 'os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=upload_fd'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver writer closed before read owner adoption', replaceRegionOnce(verifier, '\ndef handoff_exec_uploads(', '\ndef exact_cleanup', 'files[name] = (read_fd, read_pin)\n            adopted = True\n            os.close(writer_fd)', 'os.close(writer_fd)\n            files[name] = (read_fd, read_pin)\n            adopted = True'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver read descriptor pin comparison omitted', replaceRegionOnce(verifier, '\ndef handoff_exec_uploads(', '\ndef exact_cleanup', 'read_pin != original_pin or', 'False or'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver writer close omitted', replaceRegionOnce(verifier, '\ndef handoff_exec_uploads(', '\ndef exact_cleanup', '            os.close(writer_fd)', '            pass'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver second executable handoff omitted', replaceRegionOnce(verifier, '\ndef handoff_exec_uploads(', '\ndef exact_cleanup', 'for name, expected_size, expected_sha in specs:\n        writer_fd, original_pin = files[name]', 'for name, expected_size, expected_sha in specs[:1]:\n        writer_fd, original_pin = files[name]'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver final root identity recheck omitted', replaceRegionOnce(verifier, '\ndef handoff_exec_uploads(', '\ndef exact_cleanup', '        if pin_upload(fd, name, expected_size, expected_sha) != pin:\n            fail("upload_file_identity")\n    verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)', '        if pin_upload(fd, name, expected_size, expected_sha) != pin:\n            fail("upload_file_identity")'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver original root identity recheck weakened', replaceRegionOnce(verifier, '\ndef verify_upload_root(', '\ndef handoff_exec_uploads', '(root_now.st_dev, root_now.st_ino) != held_root[:2]', 'False'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver descriptor cleanup error ignored', replaceRegionOnce(verifier, '\n    except BaseException as failure:\n        cleanup_errors = []\n        for fd, _ in files.values():', '\ntry:\n    main()', 'for fd, _ in files.values():\n            try:\n                os.close(fd)\n            except BaseException as error:\n                cleanup_errors.append(error)', 'for fd, _ in files.values():\n            try:\n                os.close(fd)\n            except BaseException as error:\n                pass'), 'both fixed uploads must transition to same-pin read-only descriptors, be adopted before one-shot writer close, and settle before spawn'],
    ['receiver internal exception catch broadened', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'except Exception as error:\n    fail_exception(error)', 'except BaseException as error:\n    fail_exception(error)'), 'receiver internal exception boundary must emit only fixed class identities and one bounded <string> line while leaving SystemExit untouched'],
    ['receiver exception detail exposed', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'SAFE_EXCEPTION_CLASSES.get(type(error), "unavailable")', 'str(error)'), 'receiver internal exception boundary must emit only fixed class identities and one bounded <string> line while leaving SystemExit untouched'],
    ['receiver exception class inventory widened', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'UnicodeError: "UnicodeError", ValueError: "ValueError",', 'UnicodeError: "UnicodeError", ValueError: "ValueError", ZeroDivisionError: "ZeroDivisionError",'), 'receiver internal exception class inventory must remain the exact finite builtin identity map'],
    ['receiver embedded traceback filename widened', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'frame.f_code.co_filename == "<string>"', 'True'), 'receiver internal exception boundary must emit only fixed class identities and one bounded <string> line while leaving SystemExit untouched'],
    ['receiver traceback frame bound widened', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'walked < 16', 'walked < 160'), 'receiver internal exception boundary must emit only fixed class identities and one bounded <string> line while leaving SystemExit untouched'],
    ['receiver exception parser widened to raw classes', replaceRegionOnce(verifier, '\nfunction boundedReceiverDiagnostic(', '\nfunction receiverDiagnosticControls(', '(AssertionError|AttributeError|IndexError|KeyError|MemoryError|OSError|OverflowError|RuntimeError|TimeoutError|TypeError|UnicodeError|ValueError|unavailable)', '(.*)'), 'receiver exception parser class and line vocabulary must remain finite and canonical'],
    ['unit switched to root', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', "'-u', 'berd'", "'-u', 'root'"), 'unit suite does not use the fixed Windows-to-WSL transport, literal berd principal, strict inventory and exact cleanup'],
    ['WSL principal UID expectation weakened', replaceRegionOnce(verifier, '\nfunction verifyWslUnitPrincipal() {', '\nfunction runUnit()', "output.trim() !== '1000'", "output.trim() !== '1001'"), 'WSL principal validator must run fixed /usr/bin/id -u as berd and require exact UID 1000'],
    ['WSL principal preflight omitted', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', 'verifyWslUnitPrincipal();', 'void 0;'), 'WSL principal UID check must be consumed before private compiler setup'],
    ['WSL identity command changed', replaceRegionOnce(verifier, '\nfunction verifyWslUnitPrincipal() {', '\nfunction runUnit()', "'/usr/bin/id', '-u'", "'/usr/bin/id', '-g'"), 'WSL principal validator must run fixed /usr/bin/id -u as berd and require exact UID 1000'],
    ['unit ambient environment', replaceRegionOnce(verifier, '\nfunction runUnit() {', '\nconst routeProxmoxReceiver', "'/usr/bin/env', '-i'", "'/usr/bin/env'"), 'unit suite does not use the fixed Windows-to-WSL transport, literal berd principal, strict inventory and exact cleanup'],
    ['kernel host target changed', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', "'-oHostName=10.0.0.3'", "'-oHostName=127.0.0.1'"), 'kernel route does not use both fixed cross-compiled images, strict direct PVE SSH transport and held local cleanup'],
    ['SSH proxy enabled', replaceRegionOnce(verifier, '\nfunction runKernel() {', '\nif (mode ===', "'-oProxyJump=none'", "'-oProxyJump=localhost'"), 'kernel route does not use both fixed cross-compiled images, strict direct PVE SSH transport and held local cleanup'],
    ['receiver drops original pidfd', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'os.pidfd_open(proc.pid, 0)', 'None'), 'fixed PVE receiver lacks bounded initial-namespace/process identity, pidfd cleanup, readable upload verification, output bounds or exact cleanup'],
    ['receiver recursive cleanup', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'if os.listdir(upload_fd):', 'if False:'), 'fixed PVE receiver lacks bounded initial-namespace/process identity, pidfd cleanup, readable upload verification, output bounds or exact cleanup'],
    ['receiver upload is write-only', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'os.O_RDWR | os.O_CREAT | os.O_EXCL', 'os.O_WRONLY | os.O_CREAT | os.O_EXCL'), 'fixed PVE receiver lacks bounded initial-namespace/process identity, pidfd cleanup, readable upload verification, output bounds or exact cleanup'],
    ['receiver cleanup marker omitted', replaceRegionOnce(verifier, '\nconst routeProxmoxReceiver = String.raw`', '\nfunction shellQuote(', 'REMOTE_OBSERVER_ROUTE_UPLOAD_CLEANUP_PASS', 'REMOTE_OBSERVER_ROUTE_CLEANUP_REMOVED'), 'fixed PVE receiver lacks bounded initial-namespace/process identity, pidfd cleanup, readable upload verification, output bounds or exact cleanup'],
  ];
  for (const [label, mutant, expectedFailure] of mutants) {
    requireSource(mutant !== verifier, `${label} source mutant did not alter its exact-once anchor`);
    let failure;
    try { assertFixedTransports(mutant, false); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${expectedFailure}`,
      `${label} mutant missed its intended finite transport guard (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
}

function assertFixtureStageDiagnostics(observer, ordinaryTest, kernel, verifyMutants = true) {
  const bufferedPublisherNeedle = 'var records [2]string; recordCount, sinkOverflow := 0, false; binding, err, traceValid := checkpointObserverRouteCollectorTrace(ctx, source, true, func(record string) { if recordCount >= len(records) { sinkOverflow = true; return }; records[recordCount] = record; recordCount++ }, observeCheckpointManagedBindingLinux); for _, record := range checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid) { fmt.Println(record) }';
  const hasBoundedGatedPublisher = (source) => source.includes(bufferedPublisherNeedle);
  const hasValidDrain = (source) => {
    const body = functionBody(source, 'checkpointObserverRouteDrainCollectorTrace(records [2]string, recordCount int, sinkOverflow, traceValid bool) []string {');
    return body.includes('!traceValid || sinkOverflow || recordCount != len(records)') &&
      body.includes('records[0] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER"') &&
      body.includes('CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=(K[1-3]|unavailable)') && body.includes('return records[:]');
  };
  const hasPostCompleteValidity = (source) => {
    const body = functionBody(source, 'checkpointObserverRouteCollectorTrace(ctx context.Context, source checkpointManagedObservationSource, fixtureAnchor bool, sink func(string), run checkpointObserverRouteCollectorRun)');
    return body.indexOf('emit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=" + phase)') >= 0 &&
      body.indexOf('emit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=" + phase)') < body.indexOf('return binding, collectErr, emissionValid');
  };
  const client = functionBody(observer, 'checkpointLocalObserverObserveWithConfig');
  const broker = functionBody(observer, 'checkpointLocalObserverServeConn');
  const notifierOriginal = functionBody(observer, 'checkpointLocalObserverReportStage');
  const verifyEvidence = (source, taggedSource) => {
    const clientEvidence = functionBody(source, 'checkpointObserverRouteClientEvidence(');
    const brokerEvidence = functionBody(source, 'checkpointObserverRouteBrokerStageFromOutput(');
    const paired = functionBody(source, 'checkpointObserverRoutePID1StageRecords(');
    const nested = functionBody(source, 'checkpointObserverRouteNestedStageRecords(');
    const nestedSitesDecl = source.indexOf('nestedSites := "1988,1346"');
    const nestedRawUse = source.indexOf('checkpointObserverRouteNestedStageRecords(nestedRaw, false, nestedSites)');
    const collector = functionBody(source, 'checkpointObserverRouteCollectorEvidence(raw []byte, overflow bool) (string, string, bool) {');
    const drain = functionBody(source, 'checkpointObserverRouteDrainCollectorTrace(records [2]string, recordCount int, sinkOverflow, traceValid bool) []string {');
    const trace = functionBody(source, 'checkpointObserverRouteCollectorTrace(ctx context.Context, source checkpointManagedObservationSource, fixtureAnchor bool, sink func(string), run checkpointObserverRouteCollectorRun)');
    const identity = functionBody(source, 'checkpointObserverRouteSameErrorIdentity(left, right error) bool {');
    const nestedSites = functionBody(taggedSource, 'checkpointObserverRouteNestedAssertionSites(');
    const record = functionBody(source, 'checkpointObserverRouteNestedDiagnosticRecord(');
    requireSource(clientEvidence.includes('len(lines) != 5') && clientEvidence.includes('lines[0] != "=== RUN   TestCheckpointObserverRouteComposedClientChild"') &&
      clientEvidence.includes('lines[4] != "FAIL"') && clientEvidence.includes('checkpointObserverRouteOwnedFailureHeader(lines[3]') &&
      clientEvidence.includes('lines[2], "    checkpoint_local_observer_kernel_linux_test.go:1346: fixed signed local managed route') &&
      brokerEvidence.includes('checkpointObserverRouteCollectorEvidence(raw, overflow)') && !brokerEvidence.includes('--- PASS') &&
      collector.includes('len(lines) == 3') && collector.includes('len(lines) != 5') &&
      collector.includes('CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER') && collector.includes('CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=') &&
      collector.includes('lines[1] != "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS"') &&
      collector.includes('lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER"') &&
      collector.includes('stageMatch[1] != "B15"') &&
      identity.includes('leftValue, rightValue := reflect.ValueOf(left), reflect.ValueOf(right)') && identity.includes('leftValue.Comparable() && rightValue.Comparable() && left == right') &&
      trace.includes('return binding, collectErr, emissionValid') && hasPostCompleteValidity(source) && trace.includes('if !completed') && trace.includes('emissionValid = false') &&
      drain.includes('!traceValid || sinkOverflow || recordCount != len(records)') && drain.includes('return records[:]') &&
      nestedSitesDecl >= 0 && nestedRawUse > nestedSitesDecl &&
      paired.includes('client < "C01" || client > "C34"') && paired.includes('!validClient') &&
      nested.includes('markers != 1') && nested.includes('headers != 1') && nested.includes('summaries != 1') &&
      nested.includes('state = 1') && nested.includes('state = 2') && nested.includes('state = 3') &&
      nested.includes('state != 0 || runCount != 1') && nested.includes('state != 3') && nested.includes('state != 4') &&
      nested.includes('return "unavailable", "unavailable", "unavailable"') &&
      nested.includes('            checkpoint_local_observer_kernel_linux_test.go:1346: client=') &&
      !nested.includes('CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY') &&
      nested.includes('broker != "unavailable" && client == "unavailable"') &&
      nested.includes('broker != "B15"') && nested.includes('return client, broker, phase') &&
      nestedSites.includes('failCount != 1') && nestedSites.includes('{ invalid = true }') &&
      nestedSites.includes('passStage != 0') && nestedSites.includes('passStage != 1') &&
      nestedSites.includes('const continuation = "            checkpoint_local_observer_kernel_linux_test.go:"') &&
      record.includes('len(base+suffix) <= 128') && record.includes('suffix = " client=" + client') && record.includes('phase == "K1" || phase == "K2" || phase == "K3"') &&
      record.includes('if phase == "K1" || phase == "K2" || phase == "K3" { suffix = " client=" + client;') &&
      record.includes('return base'),
    'actual client, active broker, paired nested reducers must enforce exact finite order, ownership, association and byte fallback');
    const twoPairStart = collector.indexOf('if len(lines) == 7 {');
    const twoPairEnd = collector.indexOf('\n\tif len(lines) != 5', twoPairStart);
    const twoPairBranch = twoPairStart >= 0 && twoPairEnd > twoPairStart ? collector.slice(twoPairStart, twoPairEnd) : '';
    requireSource(twoPairBranch.includes('if len(lines) == 7 {') &&
      twoPairBranch.includes('lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || lines[4] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER"') &&
      twoPairBranch.includes('for _, index := range []int{3, 5}') &&
      twoPairBranch.includes('^CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=(K[1-3]|unavailable)$') &&
      twoPairBranch.includes('lines[index])') && twoPairBranch.includes('FindStringSubmatch(lines[6])') &&
      twoPairBranch.includes('stageMatch[1] < "B19" || stageMatch[1] > "B38"') &&
      twoPairBranch.includes('return stageMatch[1], "unavailable", true') &&
      (twoPairBranch.match(/return stageMatch\[1\], "unavailable", true/g) || []).length === 1,
    'two-pair reducer branch must enforce exact seven-line cardinality, ordered pairs, final B19-B38 association and unconditional K suppression');
    requireSource(source.includes('checkpointObserverRouteCollectorEvidence(collectorB14Raw, false)') &&
      source.includes('!valid || stage != "B14" || phase != "unavailable"') &&
      source.includes('for _, raw := range collectorRejects { if _, phase, valid := checkpointObserverRouteCollectorEvidence(raw, false); valid {'),
    'valid five-line B14 evidence must remain a positive with unavailable K while malformed transcripts remain rejected');
    requireSource(source.includes('checkpointObserverRouteClientStageFromOutput(clientRaw, false)') &&
      source.includes('checkpointObserverRouteBrokerStageFromOutput(brokerRaw, false)') &&
      source.includes('checkpointObserverRouteNestedStageRecords(nestedRaw, false, nestedSites)') &&
      source.includes('checkpointObserverRouteNestedDiagnosticRecord("signal:64"') &&
      source.includes('checkpointObserverRouteNestedDiagnosticRecord("unavailable"') &&
      source.includes('reordered client records') && source.includes('reordered broker records') &&
      source.includes('foreign extra content') && source.includes('future broker completion record') &&
      source.includes('valid one-pair non-B15 phase suppression positive rejected') &&
      source.includes('malformed nested transcript retained stages'),
    'actual parser helpers must be exercised by producer-order positives before malformed and adversarial controls');
    requireSource(source.includes('ReportStage(falseAnchor, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1') &&
      source.includes('ReportStage(nilSink, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1') &&
      source.includes('defer func() { resultErr = checkpointLocalObserverReportStage(stageConfig, checkpointLocalObserverStageC14, resultErr) }()') &&
      source.includes('if !operationPanicked || stageCalls != panicCallbacksBefore+1'),
    'ordinary controls must independently bind both fixture guards and prove panic propagation through nonnil reporting');
    requireSource(source.includes('"K1 full receiver path"') &&
      source.includes('"K2 full receiver path"') && source.includes('"K3 full receiver path"') &&
      source.includes('invalid anchor') && source.includes('incomplete record pair') &&
      source.includes('overflowed sink') && source.includes('malformed completion grammar') &&
      source.includes('append-then-panic %s published finite evidence') &&
      source.includes('checkpointObserverRouteCollectorEvidence(raw, false)'),
    'ordinary controls must exercise same actual helper, bounded gated drain and receiver for K positives and fault negatives');
    const collectCall = 'checkpointLocalObserverCollectWithConfig(ctx, config)';
    const firstCollect = broker.indexOf('first, err := ' + collectCall);
    const secondCollect = broker.indexOf('second, err := ' + collectCall);
    requireSource((broker.match(/checkpointLocalObserverCollectWithConfig\(ctx, config\)/g) || []).length === 2 && firstCollect >= 0 && secondCollect > firstCollect &&
      source.includes('two collect first-success second-success') && source.includes('two collect first-success second-error') &&
      source.includes('identical two-collection unavailable evidence positive rejected') &&
      source.includes('malformed collector evidence was accepted') && hasBoundedGatedPublisher(taggedSource),
    'two-collection evidence must bind exact ordered production callsites, bounded per-call publication, and B19-B38 receiver framing');
  };
  const verify = (source, taggedSource = kernel) => {
    const clientBody = functionBody(source, 'checkpointLocalObserverObserveWithConfig');
    const brokerBody = functionBody(source, 'checkpointLocalObserverServeConn');
    const notifier = functionBody(source, 'checkpointLocalObserverReportStage');
    const code = functionBody(source, 'checkpointLocalObserverStageCode');
    const production = functionBody(source, 'checkpointLocalObserverProductionConfig');
    const clientNeedles = [
      'os.Geteuid() == 0', 'checkpointLocalObserverReadPublicKey(config)', 'checkpointLocalObserverPinSocket(config)',
      'checkpointLocalObserverOpenCurrent(os.Getpid())', 'self.uid == 0', 'rand.Read(nonceRaw[:])',
      'checkpointLocalObserverCanonicalRequest(nonce)', 'dialer.DialContext(ctx, "unix", address.String())', 'conn.SetDeadline(deadline)',
      'checkpointLocalObserverCheckSocketPin(socketPin)', 'checkpointLocalObserverPeer(conn)', 'checkpointLocalObserverOpenCrossUID(peerPID)',
      'broker.uid != 0', 'checkpointLocalObserverWriteFull(conn, request)', 'conn.CloseWrite()', 'io.ReadAll(',
      'checkpointLocalObserverCheckFilePin(pubPin)', 'checkpointLocalObserverVerify(wire, public, nonce', 'checkpointLocalObserverProcessGID(self.pid)',
      'checkpointLocalObserverOpenCrossUID(result.Worker.PID)', 'worker.start != result.Worker.StartTicks',
      'checkpointLocalObserverOpenCrossUID(result.Worker.PID)', 'workerAgain.start != worker.start',
      'checkpointLocalObserverOpenCrossUID(peerPID)', 'brokerAgain.uid != broker.uid', 'checkpointLocalObserverOpenCurrent(self.pid)',
      'checkpointLocalObserverIdentityOf(selfAgain)', 'checkpointLocalPIDFDAlive(self.pidfd)', 'checkpointLocalPIDFDAlive(broker.pidfd)',
      'checkpointLocalPIDFDAlive(worker.pidfd)', 'checkpointLocalPIDFDAlive(workerAgain.pidfd)', 'checkpointLocalPIDFDAlive(brokerAgain.pidfd)',
      'checkpointLocalObserverCheckFilePin(pubPin)', 'checkpointLocalObserverCheckSocketPin(socketPin)',
    ];
    const brokerNeedles = [
      'conn.SetDeadline(deadline)', 'markerErr != nil', 'peer credentials are not allowlisted', 'checkpointLocalObserverOpenCurrent(peerPID)',
      'checkpointLocalObserverProcessGID(peerPID)', 'io.ReadAll(', 'checkpointLocalObserverDecodeRequest(input)',
      'checkpointLocalObserverRecheckPins(pins, private)', 'checkpointLocalObserverCheckSocketPin(socketPin)', 'checkpointLocalPIDFDAlive(held.pidfd)',
      'checkpointLocalObserverIdentityOf(peer)', 'checkpointLocalObserverOpenCurrent(1)', 'initProcess.uid != 0',
      'checkpointLocalObserverIdentityOf(initProcess)', 'checkpointLocalObserverCollectWithConfig(ctx, config)',
      'checkpointLocalObserverOpenCurrent(first.Association.Identity.PID)', 'worker1.uid != 0', 'checkpointLocalObserverIdentityOf(worker1)',
      'checkpointLocalObserverCollectWithConfig(ctx, config)', 'checkpointLocalObserverOpenCurrent(second.Association.Identity.PID)',
      'checkpointLocalObserverIdentityOf(worker2)', 'checkpointLocalObserverRecheckPins(pins, private)', 'checkpointLocalObserverCheckSocketPin(socketPin)',
      'checkpointLocalPIDFDAlive(held.pidfd)', 'checkpointLocalObserverOpenCurrent(peerPID)', 'checkpointLocalObserverOpenCurrent(1)',
      'checkpointLocalObserverOpenCurrent(worker1.pid)', 'checkpointLocalObserverIdentityOf(peerAgain)',
      'checkpointLocalObserverIdentityOf(initAgain)', 'checkpointLocalObserverIdentityOf(workerAgain)',
      '!checkpointLocalObserverIdentityMatches(caller, peerIdentity)', 'config.fixturePayloadMutator(&payload)',
      'config.fixtureMutationResult(mutation, err == nil)', 'if err != nil',
      'checkpointLocalObserverRecheckPins(pins, private)', 'checkpointLocalObserverCheckSocketPin(socketPin)',
      'checkpointLocalPIDFDAlive(held.pidfd)', 'checkpointLocalObserverWriteFull(conn, wire)',
    ];
    const checkBranches = (body, prefix, needles) => {
      const matches = [...body.matchAll(/^[ \t]*stage = checkpointLocalObserverStage([CB][0-9]{2})\r?\n[ \t]*return /gm)];
      requireSource(matches.length === needles.length, `${prefix} stage count must exactly cover every original error return`);
      let previous = body.indexOf('\n') + 1;
      for (let index = 0; index < needles.length; index++) {
        const expected = `${prefix}${String(index + 1).padStart(2, '0')}`;
        const match = matches[index];
        requireSource(match[1] === expected, `${expected} must remain bound to its original ordered failure branch`);
        const returnEnd = body.indexOf('\n', match.index + match[0].length);
        const branch = body.slice(previous, returnEnd < 0 ? body.length : returnEnd);
        requireSource(branch.includes(needles[index]), `${expected} is not bound to its actual operation or condition`);
        previous = match.index + match[0].length;
      }
    };
    checkBranches(clientBody, 'C', clientNeedles);
    checkBranches(brokerBody, 'B', brokerNeedles);
    requireSource(clientBody.includes('func checkpointLocalObserverObserveWithConfig') &&
      clientBody.includes('(result CheckpointLocalObserverResult, resultErr error)') &&
      clientBody.includes('defer func() { resultErr = checkpointLocalObserverReportStage(config, stage, resultErr) }()') &&
      brokerBody.includes('(resultErr error)') &&
      brokerBody.includes('defer func() { resultErr = checkpointLocalObserverReportStage(config, stage, resultErr) }()'),
    'named error returns must report only the original final error after each existing operation');
    requireSource(notifier.includes('cause == nil') && notifier.includes('!config.fixtureAnchor') &&
      notifier.includes('config.fixtureStageSink == nil') && notifier.includes('defer func() { _ = recover() }()') &&
      notifier.includes('config.fixtureStageSink(stage)') && notifier.includes('return cause') &&
      code.includes('checkpointLocalObserverStageC34') && code.includes('checkpointLocalObserverStageB38') &&
      !production.includes('fixtureStageSink'),
    'non-authoritative notifier must be fixture guarded, nil-error guarded, panic-contained and absent in production');
    requireSource(ordinaryTest.includes('sentinel identity') && ordinaryTest.includes('callback panic') &&
      ordinaryTest.includes('false fixture anchor invoked') && ordinaryTest.includes('nil fixture sink changed') &&
      ordinaryTest.includes('original operation panic') && ordinaryTest.includes('checkpointObserverRouteNestedDiagnosticRecord') &&
      ordinaryTest.includes('maximum bounded nested record') && ordinaryTest.includes('overlong nested suffix') &&
      ordinaryTest.includes('production configuration enabled fixture stage reporting') &&
      ordinaryTest.includes('binding_version') && ordinaryTest.includes('binding_incarnation') && ordinaryTest.includes('binding_bytes') &&
      ordinaryTest.includes('duplicate client marker') && ordinaryTest.includes('duplicate broker marker') &&
      ordinaryTest.includes('checkpointObserverRoutePID1StageRecords') &&
      ordinaryTest.includes('reordered client records') && ordinaryTest.includes('future broker completion record') &&
      ordinaryTest.includes('nested owned-site stage positive') && ordinaryTest.includes('malformed nested transcript retained stages') &&
      ordinaryTest.includes('CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS') &&
      ordinaryTest.includes('CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY') &&
      ordinaryTest.includes('checkpoint_local_observer_kernel_linux_test.go:1346: client=C15') &&
      ordinaryTest.includes('checkpoint_local_observer_kernel_linux_test.go:1346: client=C14\\n--- FAIL'),
    'ordinary existing test must cover callback identity, panic containment, binding priority and bounded marker pairing');
    requireSource(ordinaryTest.includes('falseAnchor := checkpointLocalObserverRuntimeConfig{fixtureStageSink:') &&
      ordinaryTest.includes('ReportStage(falseAnchor, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1') &&
      ordinaryTest.includes('nilSink := checkpointLocalObserverRuntimeConfig{fixtureAnchor: true}') &&
      ordinaryTest.includes('ReportStage(nilSink, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1') &&
      ordinaryTest.includes('defer func() { operationPanicked = recover() == "operation panic" }()') &&
      ordinaryTest.includes('if !operationPanicked || stageCalls != panicCallbacksBefore+1') &&
      ordinaryTest.includes('nilErrorPanicPropagated') && ordinaryTest.includes('nilErrorPanicCallbacksBefore') &&
      ordinaryTest.includes('typed-nil error identity') && ordinaryTest.includes('direct noncomparable error was not preserved as unavailable') &&
      ordinaryTest.includes('nested callback panic was recovered, suppressed, or emitted a false COMPLETE') &&
      ordinaryTest.includes('if !nilErrorPanicPropagated || stageCalls != nilErrorPanicCallbacksBefore'),
    'the ordinary test independently proves both notifier guard predicates and propagation of an original operation panic');
    verifyEvidence(ordinaryTest, taggedSource);
    requireSource(taggedSource.includes('fixtureStageSink: func(stage checkpointLocalObserverStage) { clientStage = stage }') &&
      taggedSource.includes('REMOTE_OBSERVER_ROUTE_CLIENT %s\\n') && taggedSource.includes('REMOTE_OBSERVER_ROUTE_BROKER stage=%s\\n') &&
      taggedSource.includes('exec.Command(executable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedKernelFixture$",') &&
      taggedSource.includes('exec.Command(workerExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedBrokerChild$",') &&
      taggedSource.includes('exec.Command(clientExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedClientChild$",') &&
      taggedSource.includes('REMOTE_OBSERVER_ROUTE_PID1 client=%s broker=%s%s%s') &&
      taggedSource.includes('clientRecord, brokerRecord, phaseSuffix, clientSource := checkpointObserverRoutePID1FailureRecord') &&
      hasBoundedGatedPublisher(taggedSource) &&
      taggedSource.includes('checkpointObserverRouteNestedStageRecords(data, overflow, assertions)') &&
      !taggedSource.includes('REMOTE_OBSERVER_ROUTE_PID1 client=%s broker=%s%s", err'),
    'tagged route must emit only fixed guarded client/broker markers and bind the PID1 record to the existing sites');
  };
  verify(observer);
  if (!verifyMutants) return;
  const mutations = [
    ['client branch stage moved', client, client.replace('stage = checkpointLocalObserverStageC14', 'stage = checkpointLocalObserverStageTEMP').replace('stage = checkpointLocalObserverStageC15', 'stage = checkpointLocalObserverStageC14').replace('stage = checkpointLocalObserverStageTEMP', 'stage = checkpointLocalObserverStageC15')],
    ['broker stage made foreign', broker, broker.replace('stage = checkpointLocalObserverStageB38', 'stage = checkpointLocalObserverStageC38')],
    ['fixture guard removed', notifierOriginal, notifierOriginal.replace('!config.fixtureAnchor || ', '')],
    ['non-nil error guard removed', notifierOriginal, notifierOriginal.replace('cause == nil || ', '')],
    ['callback panic containment removed', notifierOriginal, notifierOriginal.replace('defer func() { _ = recover() }()', 'defer func() {}()')],
    ['original error identity replaced', notifierOriginal, notifierOriginal.replaceAll('return cause', 'return errors.New("replaced")')],
  ];
  for (const [label, original, mutant] of mutations) {
    requireSource(mutant !== original, `${label} mutant failed to change source`);
    let rejected = false;
    try { verify(observer.replace(original, mutant)); } catch { rejected = true; }
    requireSource(rejected, `diagnostic source controls accepted ${label}`);
  }
  const evidenceOriginal = ordinaryTest;
  const evidenceMutations = [
    ['client order predicate removed', 'len(lines) != 5 || lines[0] != "=== RUN   TestCheckpointObserverRouteComposedClientChild"', 'len(lines) != 5'],
    ['broker readiness requirement removed', 'lines[1] != "CHECKPOINT_OBSERVER_ROUTE_ROOT_BROKER_CHILD_PASS"', 'false'],
    ['client-paired broker guard removed', 'client < "C01" || client > "C34" || !validClient', 'false'],
    ['nested continuation indentation weakened', 'line == "            checkpoint_local_observer_kernel_linux_test.go:1346: client="+client', 'line == "    checkpoint_local_observer_kernel_linux_test.go:1346: client="+client'],
    ['nested RUN-before-marker state weakened', 'if state != 0 || runCount != 1 || line != "=== RUN   TestCheckpointObserverRouteComposedKernelFixture"', 'if runCount != 1 || line != "=== RUN   TestCheckpointObserverRouteComposedKernelFixture"'],
    ['K-first overflow fallback removed', 'if phase == "K1" || phase == "K2" || phase == "K3" { suffix = " client=" + client;', 'if false { suffix = " client=" + client;'],
    ['failed sink trace marked valid', 'return binding, collectErr, emissionValid', 'return binding, collectErr, true'],
    ['false fixture-anchor control weakened', 'ReportStage(falseAnchor, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1', 'ReportStage(falseAnchor, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 0'],
    ['true fixture nil-sink control weakened', 'ReportStage(nilSink, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 1', 'ReportStage(nilSink, checkpointLocalObserverStageC14, sentinel); got != sentinel || stageCalls != 0'],
    ['operation panic propagation control weakened', 'if !operationPanicked || stageCalls != panicCallbacksBefore+1', 'if !operationPanicked || stageCalls != panicCallbacksBefore'],
  ];
  for (const [label, before, after] of evidenceMutations) {
    requireSource(evidenceOriginal.split(before).length === 2, `${label} mutation anchor is not unique`);
    let rejected = false;
    try { verifyEvidence(evidenceOriginal.replace(before, after), kernel); } catch { rejected = true; }
    requireSource(rejected, `diagnostic source controls accepted ${label}`);
  }
  const twoPairMutations = [
    ['seven-line cardinality weakened', 'if len(lines) == 7 {', 'if len(lines) == 9 {'],
    ['second-pair ENTER ordering removed', 'lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || lines[4] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER"', 'lines[2] != "CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_ENTER" || false'],
    ['completion pair indices weakened', '[]int{3, 5}', '[]int{3, 4}'],
    ['final-stage index substituted', 'FindStringSubmatch(lines[6])', 'FindStringSubmatch(lines[5])'],
    ['two-pair K suppression weakened', 'return stageMatch[1], "unavailable", true', 'return stageMatch[1], "K2", true'],
    ['B19 lower bound weakened', 'stageMatch[1] < "B19" || stageMatch[1] > "B38"', 'stageMatch[1] < "B18" || stageMatch[1] > "B38"'],
  ];
  const twoPairPredicateFailure = 'checkpoint observer route source contract failed: two-pair reducer branch must enforce exact seven-line cardinality, ordered pairs, final B19-B38 association and unconditional K suppression';
  for (const [label, before, after] of twoPairMutations) {
    requireSource(evidenceOriginal.split(before).length === 2, `${label} mutation anchor is not unique`);
    let failure;
    try { verifyEvidence(evidenceOriginal.replace(before, after), kernel); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === twoPairPredicateFailure,
      `${label} was not rejected by its exact branch-specific predicate (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
  for (const [label, before, after] of [
    ['nested fixture RUN emission flag removed', 'exec.Command(executable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedKernelFixture$",', 'exec.Command(executable, "-test.run=^TestCheckpointObserverRouteComposedKernelFixture$",'],
    ['broker RUN emission flag removed', 'exec.Command(workerExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedBrokerChild$",', 'exec.Command(workerExecutable, "-test.run=^TestCheckpointObserverRouteComposedBrokerChild$",'],
    ['client RUN emission flag removed', 'exec.Command(clientExecutable, "-test.v", "-test.run=^TestCheckpointObserverRouteComposedClientChild$",', 'exec.Command(clientExecutable, "-test.run=^TestCheckpointObserverRouteComposedClientChild$",'],
  ]) {
    requireSource(kernel.split(before).length === 2, `${label} mutation anchor is not unique`);
    const mutant = kernel.replace(before, after);
    requireSource(!mutant.includes(before), `source mutation did not remove ${label}`);
    let failure;
    try { verify(observer, mutant); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === 'checkpoint observer route source contract failed: tagged route must emit only fixed guarded client/broker markers and bind the PID1 record to the existing sites',
      `source acceptance predicate did not reject ${label} at the intended tagged-source guard (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
  const publisherMutations = [
    ['fault-injectable seam writes wire directly', 'func(record string) { if recordCount >= len(records) { sinkOverflow = true; return }; records[recordCount] = record; recordCount++ }', 'func(record string) { fmt.Println(record) }'],
    ['deferred provisional trace drain', 'for _, record := range checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid) { fmt.Println(record) }', 'defer func() { for _, record := range checkpointObserverRouteDrainCollectorTrace(records, recordCount, sinkOverflow, traceValid) { fmt.Println(record) } }()'],
    ['unbounded provisional record queue', 'var records [2]string; recordCount, sinkOverflow := 0, false;', 'var records []string; recordCount, sinkOverflow := 0, false;'],
  ];
  requireSource(hasBoundedGatedPublisher(kernel), 'actual fixture must use the bounded source-owned post-validity publisher');
  for (const [label, before, after] of publisherMutations) {
    requireSource(kernel.split(before).length === 2, `${label} mutation anchor is not unique`);
    const mutant = kernel.replace(before, after);
    requireSource(!hasBoundedGatedPublisher(mutant), `${label} mutation did not alter its targeted publisher predicate`);
    requireSource(!hasBoundedGatedPublisher(mutant), `${label} mutation was accepted by the bounded source-owned post-validity publisher oracle`);
  }
  requireSource(hasValidDrain(ordinaryTest), 'actual shared source-owned drain must reject invalid, incomplete and arbitrary records');
  const ungatedDrain = ordinaryTest.replace('!traceValid || sinkOverflow || recordCount != len(records)', 'sinkOverflow || recordCount != len(records)');
  requireSource(ungatedDrain !== ordinaryTest && !hasValidDrain(ungatedDrain), 'unconditional provisional trace drain mutant was accepted by the same gated-drain oracle');
  const completeEmit = 'emit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=" + phase)\n\treturn binding, collectErr, emissionValid';
  const earlyValidity = ordinaryTest.replace(completeEmit, 'return binding, collectErr, emissionValid\n\temit("CHECKPOINT_OBSERVER_ROUTE_COLLECTOR_COMPLETE k=" + phase)');
  requireSource(earlyValidity !== ordinaryTest && hasPostCompleteValidity(ordinaryTest) && !hasPostCompleteValidity(earlyValidity),
    'validity sampled before COMPLETE mutation was accepted by the same post-COMPLETE source oracle');
}

function sourceContracts() {
  const protocol = sources.get(owned[0]);
  const protocolTest = sources.get(owned[1]);
  const observer = sources.get(owned[2]);
  const observerTest = sources.get(owned[3]);
  const bridge = sources.get(owned[5]);
  const bridgeLinux = sources.get(owned[6]);
  const bridgeOther = sources.get(owned[7]);
  const managed = sources.get(owned[10]);
  const managedTest = sources.get(owned[11]);
  const collector = sources.get(owned[14]);
  const localObserverTest = sources.get(owned[15]);
  const localVerifier = sources.get(owned[16]);
  const routeVerifier = sources.get(owned[18]);
  const hostKernel = sources.get(owned[4]);
  const kernel = sources.get(owned[17]);
  assertProtocol(protocol);
  assertObserverPolicy(observer);
  assertHostBridge(bridge, bridgeLinux, bridgeOther);
  assertManagedRoute(managed, collector, managedTest);
  assertComposedFixture(hostKernel, kernel);
  assertFixtureStageDiagnostics(collector, localObserverTest, kernel);
  assertDeclaredUnitInventory();
  inventoryCoverageControls();
  assertFixedTransports(routeVerifier);
  verboseInventoryControls();
  receiverParserControls();
  composedTranscriptControls();
  assertSecurityJoins(protocol, observer, bridgeLinux, managed, collector);
  assertIntendedSourceMutants(protocol, observer, bridgeLinux, managed, collector);
  requireSource(protocolTest.includes('localObserver.Role = "local-observer"') && protocolTest.includes('localObserver.PeerUID = 0') &&
    protocolTest.includes('nonroot local-observer role was accepted'), 'protocol tests cover signed root success and nonroot denial');
  requireSource(observerTest.includes('optional exact root local-observer role rejected') && observerTest.includes('overlapping root local-observer and supervisor authority was accepted'),
    'policy tests cover optional exact role and role alias rejection');
  requireSource(localVerifier.includes('assertLocalCollectorRoleRoute(linux)') && localVerifier.includes('generic fixed-supervisor collector route passed'),
    'local observer regression verifier runs a decisive collector-wrapper mutant');
  requireSource(kernel.includes('checkpointLocalObserverKernelOptIn'), 'existing bounded tagged local CPU fixture remains under explicit opt-in');

  const mutants = [
    ['response role omitted', protocol.replace('response.Role != "node-agent" && response.Role != "fixed-supervisor" && response.Role != "local-observer"', 'response.Role != "node-agent" && response.Role != "fixed-supervisor"')],
    ['local role root UID omitted', protocol.replace('(response.Role == "fixed-supervisor" || response.Role == "local-observer") && response.PeerUID != 0', 'response.Role == "fixed-supervisor" && response.PeerUID != 0')],
    ['original role requirement omitted', observer.replace('!roles["node-agent"] || !roles["fixed-supervisor"]', '!roles["node-agent"]')],
    ['role ambiguity admitted', observer.replace('if matches > 1 {', 'if false {')],
    ['container mapping unbound', observer.replace('(role == "node-agent" || role == "local-observer") && authority.CgroupRoot != nodeContainer.CgroupRoot', 'role == "node-agent" && authority.CgroupRoot != nodeContainer.CgroupRoot')],
    ['signed role ignored', bridgeLinux.replace('validateCheckpointHostGPUResponseRole(response.Role, expectedRole)', 'validateCheckpointHostGPUResponseRole(expectedRole, expectedRole)')],
    ['nonroot direct fallback', managed.replace('if euid != 0 {', 'if false {')],
    ['collector wrapper downgraded', collector.replace('nestedFootprint: observeNestedManagedCheckpointFootprintLocalObserver', 'nestedFootprint: observeNestedManagedCheckpointFootprint')],
  ];
  const predicates = [
    (v) => assertProtocol(v), (v) => assertProtocol(v), (v) => assertObserverPolicy(v), (v) => assertObserverPolicy(v),
    (v) => assertObserverPolicy(v), (v) => assertSecurityJoins(protocol, observer, v, managed, collector), (v) => assertManagedRoute(v, collector, managedTest),
    (v) => assertManagedRoute(managed, v, managedTest),
  ];
  for (let index = 0; index < mutants.length; index++) {
    const [label, mutant] = mutants[index];
    const original = index < 2 ? protocol : index < 5 ? observer : index === 5 ? bridgeLinux : index === 6 ? managed : collector;
    requireSource(mutant !== original, `${label} mutant did not alter its intended source anchor`);
    let rejected = false;
    try { predicates[index](mutant); } catch { rejected = true; }
    requireSource(rejected, `decisive source predicate accepted ${label} mutant`);
  }
  assertComposedFixture(hostKernel, kernel);
  const mutateOnce = (text, before, after, label) => {
    requireSource(text.split(before).length === 2, `${label} actual implementation anchor is not exact-once`);
    const changed = text.replace(before, after);
    requireSource(changed !== text, `${label} mutant did not change its bounded source region`);
    return changed;
  };
  const treePositiveStart = kernel.indexOf('positive:=checkpointObserverRouteBuildLocalTreeControl(t,"positive",gid);');
  const treeNegativesStart = kernel.indexOf('for _,kind:=range []string{"directory","file","unknown"}', treePositiveStart);
  const treeControlEnd = kernel.indexOf('\n\tfmt.Println("CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS")', treeNegativesStart);
  requireSource(treePositiveStart >= 0 && treeNegativesStart > treePositiveStart && treeControlEnd > treeNegativesStart, 'initial positive-first tree control region is not bounded');
  const movedTreePositive = kernel.slice(0, treePositiveStart) + kernel.slice(treeNegativesStart, treeControlEnd) + kernel.slice(treePositiveStart, treeNegativesStart) + kernel.slice(treeControlEnd);
  const composedUUIDFailure = 'composed UUID/device/process join must propagate fixed host identity through placement, pinned plan, local inventory, and signed request';
  const composedMutants = [
    ['composed UUID override omitted', hostKernel, mutateOnce(kernel, 'plan, association := managedBindingFixture(); plan.Placement.PhysicalIdentity = "GPU-00000000-0000-0000-0000-000000000019"', 'plan, association := managedBindingFixture()', 'composed UUID override omitted'), composedUUIDFailure],
    ['composed UUID override reverted to generic plan', hostKernel, mutateOnce(kernel, 'plan, association := managedBindingFixture(); plan.Placement.PhysicalIdentity = "GPU-00000000-0000-0000-0000-000000000019"', 'plan, association := managedBindingFixture(); plan.Placement.PhysicalIdentity = "GPU-00000000-0000-0000-0000-000000000001"', 'composed UUID override reverted'), composedUUIDFailure],
    ['host device UUID disconnected', replaceRegionOnce(hostKernel, '\nfunc runCheckpointGPUObserverRouteServerChild(t *testing.T) {', '\nfunc checkpointObserverRouteCheckHeldParent(fd int, path string) error {', 'UUID: kernelFixtureUUID, PCI: kernelFixturePCI', 'UUID: "GPU-00000000-0000-0000-0000-000000000001", PCI: kernelFixturePCI', 'host device UUID disconnected'), kernel, composedUUIDFailure],
    ['host process-row UUID disconnected', replaceRegionOnce(hostKernel, '\nfunc runCheckpointGPUObserverRouteServerChild(t *testing.T) {', '\nfunc checkpointObserverRouteCheckHeldParent(fd int, path string) error {', 'UUID: kernelFixtureUUID, Bytes: 128 << 20', 'UUID: "GPU-00000000-0000-0000-0000-000000000001", Bytes: 128 << 20', 'host process-row UUID disconnected'), kernel, composedUUIDFailure],
    ['composed ChildMaskUUID propagation substituted', hostKernel, mutateOnce(kernel, 'ChildMaskUUID: plan.Placement.PhysicalIdentity', 'ChildMaskUUID: "GPU-00000000-0000-0000-0000-000000000001"', 'composed ChildMaskUUID propagation substituted'), composedUUIDFailure],
    ['PID1 raw inherited FD owner omitted', hostKernel, mutateOnce(kernel, 'localRootRawFD := 3', 'localRootRawFD := -1', 'PID1 raw inherited FD owner omitted'), 'PID1 must own inherited FD3 before every fallible check and exercise actual validation-failure and successful transfer controls'],
    ['PID1 early close outcome discarded', hostKernel, mutateOnce(kernel, 'errors.Join(cause, checkpointObserverRouteCloseFD(&localRootRawFD))', 'cause', 'PID1 early close outcome discarded'), 'PID1 must own inherited FD3 before every fallible check and exercise actual validation-failure and successful transfer controls'],
    ['PID1 adoption transfer omitted', hostKernel, mutateOnce(kernel, '*rawFD = -1', '*rawFD = *rawFD', 'PID1 adoption transfer omitted'), 'PID1 must own inherited FD3 before every fallible check and exercise actual validation-failure and successful transfer controls'],
    ['initial positive removed', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {', '\nfunc TestCheckpointObserverRouteComposedClientChild(t *testing.T) {', 'positive:=checkpointObserverRouteBuildLocalTreeControl(t,"positive",gid);', '' , 'initial positive removed'), 'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives'],
    ['initial positive moved after negatives', hostKernel, movedTreePositive, 'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives'],
    ['directory custody control muted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {', '\nfunc TestCheckpointObserverRouteComposedClientChild(t *testing.T) {', 'case "directory":', 'case "directory-muted":', 'directory custody control muted'), 'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives'],
    ['file custody control muted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {', '\nfunc TestCheckpointObserverRouteComposedClientChild(t *testing.T) {', 'case "file":', 'case "file-muted":', 'file custody control muted'), 'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives'],
    ['unknown topology control muted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteLocalTreeCustodyControls(t *testing.T) {', '\nfunc TestCheckpointObserverRouteComposedClientChild(t *testing.T) {', 'case "unknown":', 'case "unknown-muted":', 'unknown topology control muted'), 'first execute a fully populated held-path and exact-cleanup positive, then separate identity-tracked directory, file, and unknown-topology negatives'],
    ['host handler disconnected', mutateOnce(hostKernel, 'handleObserverConnectionUsing(context.Background(), connection, config', 'writeLengthPrefixed(connection, nil', 'host handler disconnected'), kernel, 'outer CPU child must run the actual host handler twice against synthetic inventory only'],
    ['host binary validation removed', hostKernel, mutateOnce(kernel, 'checkpointObserverRouteValidateHostBinary(hostBinary)', 'nil', 'host binary validation removed'), 'one fixed host parent must connect the actual route-server child to a nested root collector and preserve uncertain custody'],
    ['nested collector downgraded', hostKernel, mutateOnce(kernel, 'observeCheckpointHostGPUAttributionLocalObserverUsing(callCtx', 'observeCheckpointHostGPUAttributionPlatformForRoleUsing(callCtx', 'nested collector downgraded'), 'nested root collector uses a held root broker child PID greater than one, real peer credentials, and finite pidfd/reap cleanup'],
    ['signed client disconnected', hostKernel, mutateOnce(kernel, 'checkpointLocalObserverObserveWithConfig(callCtx, config)', 'observeCheckpointManagedBindingLinux(callCtx, checkpointManagedObservationSource{})', 'signed client disconnected'), 'nested unprivileged client must perform the actual signed local IPC route, not a disconnected synthetic callback'],
    ['unprivileged binary publication removed', hostKernel, mutateOnce(kernel, 'checkpointObserverRoutePublishClientBinaryHeld(workerExecutable, clientExecutable, groupID)', '"", checkpointObserverRouteHeldPath{}, nil', 'unprivileged binary publication removed'), 'published client custody must adopt a same-name O_PATH regular-file pin with full final-stat equality before writer settlement, and propagate every failure before client start'],
    ['unknown fixture entry recursive cleanup', hostKernel, mutateOnce(kernel, 'checkpointObserverRouteRemoveExactLocalTree(localRoot, localRootPin.dev, localRootPin.inode, localPins, mountedCleanup)', 'os.RemoveAll(localRoot)', 'unknown fixture entry recursive cleanup'), 'PID1 cleanup must recheck held entry identities and preserve unknown/substituted trees'],
    ['pidfd waitability bypassed', hostKernel, mutateOnce(kernel, 'unix.Waitid(unix.P_PIDFD, pidfd, &originalInfo, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)', 'unix.Waitid(unix.P_PIDFD, pidfd, &originalInfo, unix.WEXITED|unix.WNOHANG, nil)', 'pidfd waitability bypassed'), 'exact subreaper must establish waitability through the original pidfd, settle consumed Wait independently of expected signal, and retry EINTR only within its deadline'],
    ['atomic probe pidfd omitted', hostKernel, mutateOnce(kernel, 'probe.SysProcAttr = &syscall.SysProcAttr{PidFD: &probePIDFD, Pdeathsig: syscall.SIGKILL}', 'probe.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}', 'atomic probe pidfd omitted'), 'parent-death probe must retain atomic creation pidfd custody, thread pin, live handoff and fixed child deadline'],
    ['probe self-deadline widened', hostKernel, mutateOnce(kernel, '"-test.timeout=7s"', '"-test.timeout=70s"', 'probe self-deadline widened'), 'parent-death probe must retain atomic creation pidfd custody, thread pin, live handoff and fixed child deadline'],
    ['probe reap observation removed', hostKernel, mutateOnce(kernel, 'reaped, err := checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)\n\t\tif reaped { probeReaped = true }\n\t\tif err != nil { return err }', 'reaped, err := checkpointObserverRouteWaitExactChild(probePIDFD, 3*time.Second)\n\t\tif false { probeReaped = true }\n\t\tif err != nil { return err }', 'probe reap observation removed'), 'parent-death control must prove exact parent death and subreaper Wait before marking probe reaped'],
    ['parent exact death weakened', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteParentDeathControl(', '\nfunc TestCheckpointObserverRouteParentDeathFixture(', 'status.Signal() != syscall.SIGKILL', 'false'), 'parent-death control must prove exact parent death and subreaper Wait before marking probe reaped'],
    ['held close outcome discarded', hostKernel, mutateOnce(kernel, 'closeErr = errors.Join(closeErr, checkpointObserverRouteCloseHeldPath(&pins[index]))', '_ = checkpointObserverRouteCloseHeldPath(&pins[index])', 'held close outcome discarded'), 'fixture owners must join every held and publication descriptor close outcome exactly once'],
    ['publication close outcome discarded', hostKernel, mutateOnce(kernel, 'owned := destinationFD; destinationFD = -1; result = errors.Join(result, unix.Close(owned))', 'owned := destinationFD; destinationFD = -1; _ = unix.Close(owned)', 'publication close outcome discarded'), 'published client custody must adopt a same-name O_PATH regular-file pin with full final-stat equality before writer settlement, and propagate every failure before client start'],
    ['actual fd owner clear omitted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteCloseFD(fd *int) error {', '\nfunc checkpointObserverRouteCloseFile(file **os.File) error {', '*fd = -1', '*fd = *fd'), 'fixture owners must join every held and publication descriptor close outcome exactly once'],
    ['actual fd close retried', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteCloseFD(fd *int) error {', '\nfunc checkpointObserverRouteCloseFile(file **os.File) error {', 'return unix.Close(owned)', 'closeErr := unix.Close(owned); _ = unix.Close(owned); return closeErr'), 'fixture owners must join every held and publication descriptor close outcome exactly once'],
    ['actual fd close outcome discarded', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteCloseFD(fd *int) error {', '\nfunc checkpointObserverRouteCloseFile(file **os.File) error {', 'return unix.Close(owned)', '_ = unix.Close(owned); return nil'), 'fixture owners must join every held and publication descriptor close outcome exactly once'],
    ['same-shape file substitution accepted', hostKernel, mutateOnce(kernel, 'stat.Ino != pin.inode', 'false', 'same-shape file substitution accepted'), 'creation-time custody must hold stable directory identity, allow only known directory topology changes, keep file link/size strict, and reject substitutions/unknown names'],
    ['directory path substitution accepted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteCheckHeldPaths(pins []checkpointObserverRouteHeldPath) error {', '\nfunc checkpointObserverRouteCloseHeldPath(pin *checkpointObserverRouteHeldPath) error {', 'stat.Ino != pin.inode', 'false'), 'creation-time custody must hold stable directory identity, allow only known directory topology changes, keep file link/size strict, and reject substitutions/unknown names'],
    ['mutable directory topology frozen', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteCheckHeldPaths(pins []checkpointObserverRouteHeldPath) error {', '\nfunc checkpointObserverRouteCloseHeldPath(pin *checkpointObserverRouteHeldPath) error {', '!pin.isDir && (uint64(held.Nlink)', '(uint64(held.Nlink)'), 'creation-time custody must hold stable directory identity, allow only known directory topology changes, keep file link/size strict, and reject substitutions/unknown names'],
    ['created root owner registered late', hostKernel, replaceRegionOnce(kernel, '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {', '\nfunc checkpointObserverRouteHoldRunParent()', 'hostPins = append(hostPins, rootPin)', 'hostPins = hostPins'), 'each host/local entry retains its original creation descriptor through publication, policy, launch and exact cleanup; PID1 receives the outer local-root capability'],
    ['created local directory owner registered late', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteComposedPID1(t *testing.T) {', '\nfunc checkpointObserverRouteWaitForSocket(', 'if err != nil { t.Fatalf("retain each directory\'s identity at its creation site: %v", err) }\n\t\tlocalPins = append(localPins, pin)', 'if err != nil { t.Fatalf("retain each directory\'s identity at its creation site: %v", err) }\n\t\tlocalPins = localPins'), 'every acquired directory/file owner is registered before subsequent fallible metadata work, and nested-start close errors remain joined'],
    ['local-root success close omitted', hostKernel, mutateOnce(kernel, 'if closeErr := checkpointObserverRouteCloseHeldPath(&localRootPin); closeErr != nil {\n\t\tpreservePrivateRoot = true\n\t\tt.Fatalf("outer local-root creation capability did not settle before success: %v", closeErr)\n\t}', 'if false {', 'local-root success close omitted'), 'composed success marker follows local-root and host creation-custody descriptor settlement'],
    ['namespace worker Wait owner omitted', mutateOnce(hostKernel, 'go func() { workerDone <- worker.Wait() }()', 'workerDone := make(chan error, 1)', 'namespace worker Wait owner omitted'), kernel, 'nested namespace fixture worker does not register its exact Wait immediately after Start'],
    ['namespace worker numeric kill restored', mutateOnce(hostKernel, 'if err := unix.PidfdSendSignal(workerPIDFD, syscall.SIGKILL, nil, 0); err != nil {', 'if err := worker.Process.Kill(); err != nil {', 'namespace worker numeric kill restored'), kernel, 'nested namespace fixture worker has a forbidden numeric kill fallback'],
    ['host listener close outcome discarded', mutateOnce(hostKernel, 'closeErr := owned.Close()\n\t\tresult = errors.Join(result, closeErr)\n\t\tlistenerClosed = closeErr == nil', 'closeErr := owned.Close()\n\t\t_ = closeErr\n\t\tlistenerClosed = closeErr == nil', 'host listener close outcome discarded'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host listener owner clearing omitted', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCloseAndRemoveHostListener(', '\nfunc requireKernelFixtureInitialHostNamespace()', '*listener = nil', '*listener = *listener'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host ready owner clearing omitted', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCloseAndRemoveHostListener(', '\nfunc requireKernelFixtureInitialHostNamespace()', '*readyFile = nil', '*readyFile = *readyFile'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host ready close outcome discarded', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCloseAndRemoveHostListener(', '\nfunc requireKernelFixtureInitialHostNamespace()', 'result = errors.Join(result, owned.Close())', '_ = owned.Close()'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host readiness cleanup outcome discarded', replaceRegionOnce(hostKernel, '\nfunc runCheckpointGPUObserverRouteServerChild(t *testing.T) {', '\nfunc checkpointObserverRouteCheckHeldNamedObject(', 'errors.Join(err, cleanupErr)', 'err'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host parent capability handoff omitted', hostKernel, mutateOnce(kernel, 'server.ExtraFiles = []*os.File{hostParentFile}', 'server.ExtraFiles = nil', 'host parent capability handoff omitted'), 'host server must receive and settle the original creation-time protected parent capability, not reopen a late snapshot'],
    ['host child inherited parent owner clearing omitted', mutateOnce(hostKernel, '\t\t\tparentFD = -1\n\t\t\tif err := unix.Close(owned)', '\t\t\tparentFD = parentFD\n\t\t\tif err := unix.Close(owned)', 'host child inherited parent owner clearing omitted'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host parent currentness check omitted', replaceRegionOnce(hostKernel, '\tprivateBytes, err := os.ReadFile(keyPath)', '\tlistener, err := net.ListenUnix', 'checkpointObserverRouteCheckHeldParent(parentFD, parentPath)', 'nil'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host parent named identity guard omitted', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCheckHeldParent(', '\nfunc checkpointObserverRouteCheckHeldNamedObject(', 'stat.Ino != held.Ino', 'false'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host parent actual owner clearing omitted', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCloseAndRemoveHostListener(', '\nfunc requireKernelFixtureInitialHostNamespace()', '*parentFD = -1', '*parentFD = *parentFD'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['host parent close outcome discarded', replaceRegionOnce(hostKernel, '\nfunc checkpointObserverRouteCloseAndRemoveHostListener(', '\nfunc requireKernelFixtureInitialHostNamespace()', 'if parentFD != nil && *parentFD >= 0 { owned := *parentFD; *parentFD = -1; result = errors.Join(result, unix.Close(owned)) }', 'if parentFD != nil && *parentFD >= 0 { owned := *parentFD; *parentFD = -1; _ = unix.Close(owned) }'), kernel, 'actual host owner joins listener, socket and ready-file settlement before its success marker'],
    ['nested-start local-root close outcome discarded', hostKernel, replaceRegionOnce(kernel, '\nfunc TestCheckpointObserverRouteComposedKernelFixture(t *testing.T) {', '\nfunc checkpointObserverRouteHoldRunParent()', 'could not start exact nested route fixture child: %v", errors.Join(err, closeErr)', 'could not start exact nested route fixture child: %v", err'), 'every acquired directory/file owner is registered before subsequent fallible metadata work, and nested-start close errors remain joined'],
    ['broker readiness count guard omitted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteWaitForOutputMarker(', '\nfunc checkpointLocalObserverKernelFixtureBody(', 'if overflow || strings.Count(string(stable), marker) != 1 {', 'if false {'), 'bounded broker readiness requires a stable exact-once output marker, live original pidfd, overflow and deadline checks'],
    ['PR_GET pointer ABI omitted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteGetPrctlInt(', '\nfunc TestCheckpointObserverRouteParentDeathFixture(', 'uintptr(unsafe.Pointer(&value))', '0'), 'PR_GET child-subreaper and parent-death settings must use the kernel int* output ABI, not syscall return values'],
    ['probe custody ACK omitted', hostKernel, mutateOnce(kernel, 'if ackErr != nil || ackAncillaryErr != nil || ackFlags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || ackControlN != 0 || string(ack[:ackN]) != "ACK "+nonce {', 'if false {', 'probe custody ACK omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['creator COMMIT omitted', hostKernel, mutateOnce(kernel, 'commitErr != nil || commitFlags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0 || commitControlN != 0 || string(commit[:commitN]) != "COMMIT "+nonce', 'false', 'creator COMMIT omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['local reap accepted after committed handoff', hostKernel, mutateOnce(kernel, 'return !committed && checkpointObserverRouteCreatorLocallyReaped(output, nonce)', 'return checkpointObserverRouteCreatorLocallyReaped(output, nonce)', 'local reap accepted after committed handoff'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['committed child identity join omitted', hostKernel, mutateOnce(kernel, 'if err := checkpointObserverRouteCheckProbeIdentity(probePID, parent.Process.Pid, executable); err != nil {', 'if false {', 'committed child identity join omitted'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['creator child identity join omitted', hostKernel, mutateOnce(kernel, 'if err := checkpointObserverRouteCheckProbeIdentity(probe.Process.Pid, os.Getpid(), executable); err != nil {', 'if false {', 'creator child identity join omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['creator COMMIT send omitted', hostKernel, mutateOnce(kernel, 'SendmsgN(controlFD, commit, nil, nil, 0)', 'SendmsgN(controlFD, nil, nil, nil, 0)', 'creator COMMIT send omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['probe output wait race restored', hostKernel, mutateOnce(kernel, 'probe.Stdout, probe.Stderr = probeOutput, probeOutput', 'probe.StdoutPipe()', 'probe output wait race restored'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['ACK descriptor cleanup omitted', hostKernel, mutateOnce(kernel, 'for _, fd := range ackRights { ackAncillaryErr = errors.Join(ackAncillaryErr, unix.Close(fd)) }', 'ackRights = nil', 'ACK descriptor cleanup omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['bounded socket send omitted', hostKernel, mutateOnce(kernel, 'return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 2})', 'return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 2})', 'bounded socket send omitted'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['no-child settlement omitted', hostKernel, mutateOnce(kernel, 'return !overflow && strings.Count(string(data), "CHECKPOINT_OBSERVER_ROUTE_NO_CHILD "+nonce) == 1', 'return false', 'no-child settlement omitted'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['consumed child state discarded', hostKernel, mutateOnce(kernel, 'return true, errors.New("adopted original probe was reaped without its exact parent-death SIGKILL")', 'return false, errors.New("adopted original probe was reaped without its exact parent-death SIGKILL")', 'consumed child state discarded'), 'exact subreaper must establish waitability through the original pidfd, settle consumed Wait independently of expected signal, and retry EINTR only within its deadline'],
    ['ACK ambiguity ownership lost', hostKernel, mutateOnce(kernel, 'probePIDFD, probeReaped, probeOwnershipTransferred = candidateProbePIDFD, false, true', 'probePIDFD = candidateProbePIDFD', 'ACK ambiguity ownership lost'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['received fd truncation cleanup omitted', hostKernel, mutateOnce(kernel, 'closeReceived())', 'nil)', 'received fd truncation cleanup omitted'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['handoff short-send check omitted', hostKernel, mutateOnce(kernel, 'sent != len(handoff)', 'false', 'handoff short-send check omitted'), 'original pidfd custody requires bounded nonce ACK then creator COMMIT before parent death, with truncation and short-send rejection'],
    ['creator local reap proof omitted', hostKernel, mutateOnce(kernel, 'strings.Count(string(parentText), marker) == 1', 'false', 'creator local reap proof omitted'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['subreaper restore before child settlement', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteParentDeathControl(', '\nfunc checkpointObserverRouteGetPrctlInt(', 'if parentReaped && probeReaped {', 'if true {'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
    ['MSG_TRUNC accepted', hostKernel, replaceRegionOnce(kernel, '\nfunc checkpointObserverRouteParentDeathControl(', '\nfunc checkpointObserverRouteGetPrctlInt(', 'flags&(unix.MSG_CTRUNC|unix.MSG_TRUNC) != 0', 'flags&unix.MSG_CTRUNC != 0'), 'subreaper custody path rejects both truncation flags and proves either transferred Wait4 or creator-owned local Wait before restore'],
  ];
  for (const [label, hostCandidate, nodeCandidate, expectedFailure] of composedMutants) {
    let failure;
    try { assertComposedFixture(hostCandidate, nodeCandidate); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${expectedFailure}`,
      `composed ${label} mutant missed its intended finite guard (${failure instanceof Error ? failure.message : 'accepted'})`);
  }
  const expectNodeGuard = (label, candidate, expected) => {
    let failure;
    try { assertComposedFixture(hostKernel, candidate); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === `checkpoint observer route source contract failed: ${expected}`,
      `${label} missed its intended actual-caller predicate (${failure instanceof Error ? failure.message : 'accepted'})`);
  };
  const checkedChildCloseSites = [
    ['clientPIDFD','unprivileged client original pidfd settlement failed','unprivileged client pidfd close failed'],
    ['brokerPIDFD','local broker original pidfd settlement failed','root broker pidfd close failed'],
    ['workerPIDFD','composed worker pidfd settlement failed','composed worker pidfd close failed'],
  ];
  for (const [owner, message, deferredMessage] of checkedChildCloseSites) {
    const actual = `if closeErr := checkpointObserverRouteCloseFD(&${owner}); closeErr != nil { localCleanupUncertain = true; t.Fatalf("${message}: %v", closeErr) }`;
    expectNodeGuard(`${owner} discarded outcome`, mutateOnce(kernel, actual, `_ = checkpointObserverRouteCloseFD(&${owner})`, `${owner} discarded outcome`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
    expectNodeGuard(`${owner} clear omission`, mutateOnce(kernel, actual, `if closeErr := unix.Close(${owner}); closeErr != nil { localCleanupUncertain = true; t.Fatalf("${message}: %v", closeErr) }`, `${owner} clear omission`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
    const retried = `if closeErr := errors.Join(checkpointObserverRouteCloseFD(&${owner}), checkpointObserverRouteCloseFD(&${owner})); closeErr != nil { localCleanupUncertain = true; t.Fatalf("${message}: %v", closeErr) }`;
    expectNodeGuard(`${owner} attempted retry`, mutateOnce(kernel, actual, retried, `${owner} attempted retry`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
    const deferred = `if closeErr := checkpointObserverRouteCloseFD(&${owner}); closeErr != nil { localCleanupUncertain = true; t.Errorf("${deferredMessage}: %v", closeErr) }`;
    expectNodeGuard(`${owner} failure settlement discarded`, mutateOnce(kernel, deferred, `_ = checkpointObserverRouteCloseFD(&${owner})`, `${owner} failure settlement discarded`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
    expectNodeGuard(`${owner} failure clearing omitted`, mutateOnce(kernel, deferred, `if closeErr := unix.Close(${owner}); closeErr != nil { localCleanupUncertain = true; t.Errorf("${deferredMessage}: %v", closeErr) }`, `${owner} failure clearing omitted`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
    const deferredRetry = `if closeErr := errors.Join(checkpointObserverRouteCloseFD(&${owner}), checkpointObserverRouteCloseFD(&${owner})); closeErr != nil { localCleanupUncertain = true; t.Errorf("${deferredMessage}: %v", closeErr) }`;
    expectNodeGuard(`${owner} failure attempted retry`, mutateOnce(kernel, deferred, deferredRetry, `${owner} failure attempted retry`), 'actual client, broker, and worker pidfd callers must check one clear-before-close outcome, retain uncertainty, and gate exact removal');
  }
  expectNodeGuard('sentinel setup disconnected from outer caller', mutateOnce(kernel, 'checkpointObserverRouteSentinelSetup(&sentinelFile,sentinelBytes,checkpointObserverRouteRealSentinelOps(sentinelFile))', 'checkpointObserverRouteRealSentinelOps(sentinelFile)', 'sentinel setup disconnected from outer caller'), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  const rootOwnerGuard = 'PID1 must own inherited FD3 before every fallible check and exercise actual validation-failure and successful transfer controls';
  expectNodeGuard('adopted root owner registration omitted', mutateOnce(kernel, 't.Cleanup(func() { if closeErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner); closeErr != nil { t.Errorf("adopted root capability settlement: %v", closeErr) } })', '// adopted owner cleanup omitted', 'adopted root owner registration omitted'), rootOwnerGuard);
  expectNodeGuard('adopted root owner settlement omitted', mutateOnce(kernel, 'adoptedCloseErr := checkpointObserverRouteCloseHeldPath(&adoptedOwner)', 'adoptedCloseErr := error(nil)', 'adopted root owner settlement omitted'), rootOwnerGuard);
  expectNodeGuard('adopted root owner transfer reset omitted', mutateOnce(kernel, 'pin = adoptedOwner; adoptedOwner.fd = -1', 'pin = adoptedOwner', 'adopted root owner transfer reset omitted'), rootOwnerGuard);
  expectNodeGuard('sentinel mutable creation identity omitted', mutateOnce(kernel, 'owner.dev,owner.inode,owner.known=uint64(held.Dev),held.Ino,true', 'owner.dev,owner.inode,owner.known=0,0,false', 'sentinel mutable creation identity omitted'), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  expectNodeGuard('sentinel write bytes expectation weakened', mutateOnce(kernel, 'if fault=="chmod"{expected=""}', 'if fault=="chmod"||fault=="write"{expected=""}', 'sentinel write bytes expectation weakened'), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  for (const stage of ['chmod','sync']) {
    const actual = `if err:=ops.${stage}();err!=nil{return settle(err)}`;
    expectNodeGuard(`shared sentinel ${stage} operation error ignored`, mutateOnce(kernel, actual, `if err:=ops.${stage}();false{return settle(err)}`, `shared sentinel ${stage} operation error ignored`), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  }
  for (const [label,actual,mutant] of [
    ['write','if n,err:=ops.write(contents);err!=nil{return settle(err)}','if n,err:=ops.write(contents);false{return settle(err)}'],
    ['stat','info,err:=ops.stat();if err!=nil{return settle(err)}','info,err:=ops.stat();if false{return settle(err)}'],
    ['identity','if !ok||stat.Uid!=0||info.Mode().Perm()!=0600||info.Size()!=int64(len(contents)){return settle(errors.New("sentinel creation identity mismatch"))}','if false{return settle(errors.New("sentinel creation identity mismatch"))}'],
  ]) expectNodeGuard(`shared sentinel ${label} actual guard bypassed`, mutateOnce(kernel, actual, mutant, `shared sentinel ${label} actual guard bypassed`), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  expectNodeGuard('sentinel close outcome discarded', mutateOnce(kernel, 'errors.Join(cause,ops.close(file))', 'cause', 'sentinel close outcome discarded'), 'sentinel caller must register immediately, join all early causes, clear before one close, preserve on uncertainty, and remove only after exact recheck');
  for (const [label, file, before, after] of [
    ['missing actual successful-role ambiguity top', 'internal/checkpointgpuobserver/observer_linux_test.go', 'func TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRoles(', 'func TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRolesRemoved('],
    ['missing unit top', 'internal/nodeagent/checkpoint_managed_binding_linux_test.go', 'func TestCheckpointManagedBindingObserverRoleRouting(', 'func TestCheckpointManagedBindingRoleRoutingRemoved('],
    ['missing child case', 'internal/checkpointgpuobserver/observer_linux_test.go', '"overlap_rejected"', '"overlap_accepted"'],
  ]) {
    const mutatedSource = sources.get(file);
    requireSource(mutatedSource.split(before).length === 2, `${label} source mutant anchor is not unique`);
    const mutantMap = new Map(sources);
    mutantMap.set(file, mutatedSource.replace(before, after));
    let rejected = false;
    try { assertDeclaredUnitInventory(mutantMap); } catch { rejected = true; }
    requireSource(rejected, `strict unit source inventory accepted ${label} mutant`);
  }
}

const unitInventory = {
  './internal/checkpointgpuobserver': [
    'TestRequestCanonicalValidation',
    'TestSignedResponseBindsNonceAndIncarnations',
    'TestResponseRejectsGPUAndNamespaceSubstitution',
    'TestAuthorizeObserverPeerRejectsAmbiguousSuccessfulRoles',
    'TestRepeatedNumericNSpidAcrossNamespacesIsValid',
    'TestEnvelopeRejectsDuplicateFieldsAndBadEncoding',
    ...['duplicate', 'case_variant', 'unknown', 'null', 'whitespace'].map((child) => `TestRequestCanonicalValidation/${child}`),
    ...['multiple_row_identity', 'wrong_GPU_UUID', 'namespace_device', 'namespace_inode', 'namespace_type', 'init_chain', 'empty_cgroup']
      .map((child) => `TestResponseRejectsGPUAndNamespaceSubstitution/${child}`),
    'TestObserverNamespaceTypeFromHeldCurrentPIDDescriptor',
    'TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority',
    ...['local_observer_wrong_UID', 'duplicate_local_observer_role', 'local_observer_executable_swap', 'node_agent_changed_to_root_only']
      .map((child) => `TestObserverConfigRequiresBothExactCallerRolesAndContainerAuthority/${child}`),
    'TestObserverPeerNeedsExecutableAndHostCgroupAuthority',
    'TestObserverPeerNeedsExecutableAndHostCgroupAuthority/cgroup',
    'TestObserverPeerNeedsExecutableAndHostCgroupAuthority/executable',
    'TestObserverPeerNeedsExecutableAndHostCgroupAuthority/executable_path',
    'TestObserverPeerNeedsExecutableAndHostCgroupAuthority/uid',
    'TestObserverPeerContainerSelectionRequiresUniqueOverlap',
    'TestHostNSpidParserRetainsRepeatedIDsAcrossNamespaceLevels',
    ...['node_agent', 'fixed_supervisor', 'local_observer'].map((role) => `TestObserverPeerContainerSelectionRequiresUniqueOverlap/${role}`),
    ...['node_agent', 'fixed_supervisor', 'local_observer'].flatMap((role) =>
      ['single_match', 'disjoint_sibling', 'overlap_rejected'].map((child) => `TestObserverPeerContainerSelectionRequiresUniqueOverlap/${role}/${child}`)),
    'TestGPUInventoryParserAndUniqueWorkerJoin',
    ...['absent', 'duplicate', 'wrong_GPU'].map((child) => `TestGPUInventoryParserAndUniqueWorkerJoin/${child}`),
  ],
  './internal/nodeagent': [
    'TestCheckpointObserverRouteTmpfsCustodyControls',
    ...['noexec', 'readonly', 'missing-nosuid', 'missing-nodev', 'unbounded-size', 'malformed-size', 'missing-size', 'duplicate-size', 'unbounded-inodes', 'duplicate-inodes', 'conflicting-inode-modes', 'duplicate-inode64', 'duplicate-inode32', 'malformed-inode64', 'malformed-inode32', 'wrong-mode', 'nonroot-uid', 'nonroot-gid', 'duplicate-uid', 'conflicting-uid', 'wrong-filesystem', 'zero-mount-id', 'malformed-mount-id', 'wrong-target']
      .map((child) => `TestCheckpointObserverRouteTmpfsCustodyControls/${child}`),
    ...['not-attempted', 'not-mounted', 'attempt-latched', 'outstanding-references', 'wrong-proof-mount', 'wrong-mount-id', 'missing-children-clear', 'missing-underlying-custody', 'stale-parent', 'stale-mount-path']
      .map((child) => `TestCheckpointObserverRouteTmpfsCustodyControls/unmount-${child}`),
    'TestCheckpointManagedBindingControls',
    ...['one_exact_alias', 'duplicate_alias_field', 'case_alias', 'ambiguous_model_list', 'wrong_model_object', 'no_loaded_model',
      'truncated_response', 'unexpected_metadata', 'trailing_data', 'alias_id_disagrees', 'ambiguous_aliases', 'duplicate_alias_value',
      'null_aliases', 'null_alias_member', 'null_tags', 'created_string', 'null_tag_member', 'empty_tag_member', 'null_string_id',
      'metadata_fraction', 'metadata_null', 'ftype_null', 'metadata_case_alias', 'wrong_owner', 'ftype_numeric_instead_of_string',
      'oversized_response'].map((child) => `TestCheckpointManagedBindingControls/${child}`),
    'TestCheckpointManagedBindingFaultControls',
    ...['positive_exact_argv', 'missing_argv0', 'context_substitution', 'slot_substitution', 'model_operand_confusion', 'descriptor_confusion',
      'staged_executable_argv0', 'extra_argv', 'snapshot_root_substitution', 'placement_flag_substitution', 'empty_argument']
      .map((child) => `TestCheckpointManagedBindingFaultControls/${child}`),
    'TestCheckpointManagedBindingFreshnessControls',
    'TestCheckpointManagedBindingUnsupportedPlatform',
    'TestCheckpointHostGPUObservationRequiresExactPinnedPhysicalPlacement',
    ...['missing_bytes', 'wrong_response_bytes', 'wrong_process_UUID', 'wrong_plan_UUID', 'missing_PCI']
      .map((child) => `TestCheckpointHostGPUObservationRequiresExactPinnedPhysicalPlacement/${child}`),
    'TestCheckpointHostGPUObservationBindsPlannedPCIBus',
    'TestCheckpointHostObserverFramingBoundsAndRoundTrip',
    'TestCheckpointBridgeNamespaceTypeFromHeldCurrentPIDDescriptor',
    'TestCheckpointObserverFrameWriterHandlesShortWritesAndZeroProgress',
    'TestCheckpointObserverTrustPinDetectsContentAndPathSubstitution',
    'TestCheckpointObserverSignedResponseRoleWrappers',
    'TestCheckpointManagedBindingNestedObserverRouteAndNoFallback',
    'TestCheckpointManagedBindingObserverRoleRouting',
    ...['canceled', 'deadline', 'key_unavailable', 'socket_unavailable', 'stale_response', 'signature_invalid']
      .map((child) => `TestCheckpointManagedBindingObserverRoleRouting/${child}`),
    'TestCheckpointManagedBindingOrchestrationPositive',
    'TestCheckpointManagedBindingOrchestrationFaultControls',
    ...['staged_artifact_mismatch', 'argv0_staged_path_confusion', 'context_changed', 'ambiguous_current_alias',
      'wrong_initial_current_alias', 'physical_footprint_outside_plan', 'missing_physical_attribution', 'plan_substitution_at_final_recheck',
      'process_incarnation_changed', 'start_ticks_changed', 'listener_socket_changed', 'unit_invocation_changed', 'unit_cgroup_changed']
      .map((child) => `TestCheckpointManagedBindingOrchestrationFaultControls/${child}`),
    'TestCheckpointManagedBindingObservationFreshness',
    'TestCheckpointManagedBindingAssociationTupleControls',
    ...['identity_evidence', 'endpoint', 'service_unit', 'boot_id', 'pid', 'start_ticks', 'listener_ip', 'listener_port', 'listener_socket',
      'executable_path', 'executable_hash', 'executable_device', 'executable_inode', 'executable_size', 'model_path', 'model_hash',
      'model_device', 'model_inode', 'model_size', 'invocation', 'cgroup', 'receipt_evidence', 'receipt_model_argument', 'receipt_argv_hash',
      'receipt_binding_hash', 'receipt_nonce', 'receipt_endpoint', 'receipt_unit', 'receipt_unit_association', 'receipt_boot_id', 'receipt_pid',
      'receipt_start_ticks', 'receipt_socket', 'receipt_executable_path', 'receipt_executable_hash', 'receipt_alias', 'artifact_path',
      'artifact_device', 'artifact_inode', 'artifact_size', 'artifact_hash', 'artifact_verity', 'receipt_executable_device',
      'receipt_executable_inode', 'receipt_executable_size', 'receipt_executable_verity', 'timestamps_and_measured_footprint_excluded']
      .map((child) => `TestCheckpointManagedBindingAssociationTupleControls/${child}`),
    'TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation',
    ...['namespace', 'peer_PID', 'start_ticks', 'boot_ID', 'UID', 'executable'].map((child) => `TestCheckpointObserverPeerJoinRejectsStaleLocalIncarnation/${child}`),
  ],
};

function exactGoJSONInventory(output, expected, description) {
  const counts = new Map();
  for (const [index, line] of output.split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error(`${description}: non-JSON go test output at line ${index + 1}`); }
    if (!['run', 'pass', 'fail', 'skip'].includes(event.Action) || typeof event.Test !== 'string') continue;
    const key = `${event.Action}:${event.Test}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const failures = [];
  for (const name of expected) {
    if (counts.get(`run:${name}`) !== 1) failures.push(`run:${name}`);
    if (counts.get(`pass:${name}`) !== 1) failures.push(`pass:${name}`);
    if ((counts.get(`fail:${name}`) ?? 0) || (counts.get(`skip:${name}`) ?? 0)) failures.push(`failed-or-skipped:${name}`);
  }
  for (const key of counts.keys()) {
    const [action, name] = key.split(':', 2);
    if (!expected.includes(name) || !['run', 'pass'].includes(action)) failures.push(`unexpected:${key}`);
  }
  if (failures.length) throw new Error(`${description}: exact RUN/PASS inventory mismatch (${failures.join(', ')})`);
}

function invoke(program, args, options, description) {
  const result = spawnSync(program, args, {
    cwd: options.cwd ?? root, encoding: options.encoding ?? 'utf8', timeout: options.timeout, maxBuffer: options.maxBuffer ?? 8 * 1024 * 1024,
    windowsHide: true, env: options.env ?? process.env, input: options.input,
  });
  if (options.receiverDiagnostic && options.diagnosticLimit) throw new Error('receiver diagnostics cannot reuse compiler diagnostics');
  const failed = Boolean(result.error) || result.status !== 0;
  const diagnostic = failed && options.receiverDiagnostic ? boundedReceiverDiagnostic(result) :
    options.diagnosticLimit ? boundedCompilerDiagnostic(result, options.diagnosticLimit) : '';
  if (result.error) throw new Error(`${description}: process could not be confirmed (${result.error.code ?? 'unavailable'})${diagnostic}`);
  if (result.status !== 0) throw new Error(`${description}: exited ${result.status ?? 'without a status'}${diagnostic}`);
  return options.encoding === 'buffer' ? Buffer.concat([result.stdout ?? Buffer.alloc(0), result.stderr ?? Buffer.alloc(0)]) : `${result.stdout ?? ''}${result.stderr ?? ''}`;
}

function boundedCompilerDiagnostic(result, limit) {
  if (limit !== 4096) throw new Error('compiler diagnostic limit is not the fixed 4-KiB bound');
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`
    .replace(/[\u001b\u009b][[\]()#;?]*(?:(?:[a-zA-Z\d]*(?:;[a-zA-Z\d]*)*)?\u0007|(?:\d{1,4}(?:;\d{0,4})*)?[\dA-PR-TZcf-nq-uy=><~])/g, '')
    .replace(/[A-Za-z]:\\Users\\[^\\\r\n]+/gi, '<user-home>')
    .replace(/\0/g, '?')
    .replace(/[^\x09\x0a\x0d\x20-\x7e]/g, '?');
  return output ? `\ncompiler diagnostic (last at most ${limit} characters; user-home redacted):\n${output.slice(-limit)}` : '';
}

const receiverFailureStages = new Set([
  'host_identity', 'initial_pid_namespace', 'binary_bound', 'upload_file_identity', 'upload_bytes_or_path',
  'upload_elf_identity', 'cleanup_unexpected_entries', 'cleanup_file_identity', 'cleanup_root_identity',
  'cleanup_tmp_identity', 'cleanup_file_absence', 'cleanup_root_absence', 'cleanup_tmp_recheck', 'arguments',
  'tmp_preflight', 'tmp_identity', 'upload_root', 'upload_truncated', 'upload_write', 'upload_digest_or_elf',
  'upload_trailing_bytes', 'test_process_identity', 'test_timeout', 'test_output_bound', 'child_descriptor_settlement',
  'test_nonzero', 'receiver_exception', 'malformed_run_record', 'malformed_result_record', 'test_runpass_inventory', 'test_marker_inventory_or_order',
]);

function boundedReceiverDiagnostic(result) {
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (Buffer.byteLength(output, 'utf8') > 3 * 1024 * 1024) return '';
  const records = output.split(/\r?\n/).filter((line) => line.length !== 0);
  if (records.length === 0 || records.length > 18) return '';
  let stage = '';
  const locations = [];
  let exception = null;
  let nested = null;
  for (const line of records) {
    if (line.length > 128) return '';
    const stageMatch = /^REMOTE_OBSERVER_ROUTE_FAILURE stage=([a-z_]{1,48})$/.exec(line);
    if (stageMatch) {
      if (stage || !receiverFailureStages.has(stageMatch[1])) return '';
      stage = stageMatch[1];
      continue;
    }
    const exceptionMatch = /^REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=(AssertionError|AttributeError|IndexError|KeyError|MemoryError|OSError|OverflowError|RuntimeError|TimeoutError|TypeError|UnicodeError|ValueError|unavailable) line=(unavailable|[1-9][0-9]{0,2}|1000)$/.exec(line);
    if (exceptionMatch) {
      if (exception) return '';
      exception = { className: exceptionMatch[1], line: exceptionMatch[2] };
      continue;
    }
    const nestedMatch = /^REMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=(unavailable|code:[1-9][0-9]{0,2}|signal:[1-9][0-9]?) overflow=(yes|no) assertions=(unavailable|[1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,3})(?: client=(C[0-9]{2})(?: broker=(B[0-9]{2})(?: k=(K[1-3]))?)?)?$/.exec(line);
    if (nestedMatch) {
      if (nested) return '';
      const exitValue = nestedMatch[1];
      if (exitValue.startsWith('code:') && Number(exitValue.slice(5)) > 255) return '';
      if (exitValue.startsWith('signal:') && Number(exitValue.slice(7)) > 64) return '';
      const assertions = nestedMatch[3] === 'unavailable' ? [] : nestedMatch[3].split(',').map(Number);
      if (assertions.some((value) => value > 4800) || new Set(assertions).size !== assertions.length) return '';
      const clientNumber = nestedMatch[4] === undefined ? 0 : Number(nestedMatch[4].slice(1));
      const brokerNumber = nestedMatch[5] === undefined ? 0 : Number(nestedMatch[5].slice(1));
      if ((nestedMatch[4] !== undefined && (clientNumber < 1 || clientNumber > 34)) || (nestedMatch[5] !== undefined && (brokerNumber < 1 || brokerNumber > 38))) return '';
      if (nestedMatch[2] === 'yes' && (nestedMatch[4] !== undefined || nestedMatch[5] !== undefined)) return '';
      if (nestedMatch[5] !== undefined && nestedMatch[4] === undefined) return '';
      if ((nestedMatch[4] !== undefined || nestedMatch[5] !== undefined) && (!assertions.includes(1988) || !assertions.includes(1346))) return '';
      if (nestedMatch[6] !== undefined && (nestedMatch[2] !== 'no' || nestedMatch[4] === undefined || nestedMatch[5] !== 'B15' || !assertions.includes(1988) || !assertions.includes(1346))) return '';
      nested = { exitValue, overflow: nestedMatch[2], assertions: nestedMatch[3], client: nestedMatch[4] || '', broker: nestedMatch[5] || '', phase: nestedMatch[6] || '' };
      continue;
    }
    const locationMatch = /^REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test\.go:([1-9][0-9]{0,3})$/.exec(line);
    if (!locationMatch) return '';
    const lineNumber = Number(locationMatch[1]);
    if (lineNumber > 4800 || locations.length >= 16 || locations.includes(lineNumber)) return '';
    locations.push(lineNumber);
  }
  if (!stage || (locations.length !== 0 && stage !== 'test_nonzero') || (nested && stage !== 'test_nonzero') ||
      (exception && (stage !== 'receiver_exception' || locations.length !== 0)) ||
      (stage === 'receiver_exception' && !exception)) return '';
  const sourceLocations = locations.length === 0 ? '' : ` source_locations=${locations.map((line) => `checkpoint_local_observer_kernel_linux_test.go:${line}`).join(',')}`;
  const exceptionDetail = exception ? ` exception_class=${exception.className} embedded_line=${exception.line}` : '';
  const nestedDetail = nested ? ` nested_exit=${nested.exitValue} nested_overflow=${nested.overflow} nested_assertions=${nested.assertions}${nested.client ? ` client=${nested.client}` : ''}${nested.broker ? ` broker=${nested.broker}` : ''}${nested.phase ? ` k=${nested.phase}` : ''}` : '';
  return `\nremote receiver diagnostic: stage=${stage}${sourceLocations}${exceptionDetail}${nestedDetail}`;
}

function receiverDiagnosticControls() {
  const positive = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero',
    'REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:245',
    'REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:2107',
  ].join('\n');
  const expected = '\nremote receiver diagnostic: stage=test_nonzero source_locations=checkpoint_local_observer_kernel_linux_test.go:245,checkpoint_local_observer_kernel_linux_test.go:2107';
  requireSource(boundedReceiverDiagnostic({ stdout: positive, stderr: '' }) === expected,
    'receiver diagnostic positive control did not retain only bounded structured locations');
  const rejects = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test nonzero',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=unknown_stage',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:1549 secret=token',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=cleanup_root_identity\nREMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:1549',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:4801',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\n' + Array.from({ length: 17 }, (_, index) => `REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:${100 + index}`).join('\n'),
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE RECEIVER RAW PRIVATE MESSAGE /tmp/key=secret',
  ];
  requireSource(rejects.every((sample) => boundedReceiverDiagnostic({ stdout: '', stderr: sample }) === ''),
    'receiver diagnostic negative controls accepted malformed, injected, unbounded, or stage-inconsistent output');
}

function pythonNestedHopControls(nestedReceiver) {
  const marker = 'REMOTE_OBSERVER_ROUTE_NESTED ';
  const wrappedPrefix = `        ${marker}`;
  const runRecord = '=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n';
  const failureRecord = '--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\n';
  const outerFailure = '    checkpoint_local_observer_kernel_linux_test.go:625: child test failed\n';
  const transcript = (nestedLines = '') => `${runRecord}${outerFailure}${nestedLines}${failureRecord}`;
  const parseRaw = (text) => {
    const records = [];
    for (const line of text.split(/\r?\n/)) {
      if (!line.includes('REMOTE_OBSERVER_ROUTE_NESTED')) continue;
      if (!line.startsWith(wrappedPrefix)) throw new Error('malformed_result_record');
      records.push(line.slice(wrappedPrefix.length));
    }
    if (records.length === 0) return null;
    if (records.length !== 1) throw new Error('malformed_result_record');
    const fullRecord = marker + records[0];
    if (/[^\x00-\x7f]/.test(fullRecord) || Buffer.byteLength(fullRecord, 'ascii') > 128) throw new Error('malformed_result_record');
    const match = /^stage=test_nonzero exit=(unavailable|code:[1-9][0-9]{0,2}|signal:[1-9][0-9]?) overflow=(yes|no) assertions=(unavailable|[1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,3})(?: client=(C[0-9]{2})(?: broker=(B[0-9]{2})(?: k=(K[1-3]))?)?)?$/.exec(records[0]);
    if (!match) throw new Error('malformed_result_record');
    const [, exitValue, overflow, assertions, client, broker, phase] = match;
    if (exitValue.startsWith('code:') && Number(exitValue.slice(5)) > 255) throw new Error('malformed_result_record');
    if (exitValue.startsWith('signal:') && Number(exitValue.slice(7)) > 64) throw new Error('malformed_result_record');
    if (assertions !== 'unavailable') {
      const values = assertions.split(',').map(Number);
      if (values.some((value) => value > 4800) || new Set(values).size !== values.length) throw new Error('malformed_result_record');
    }
    if (client && !(Number(client.slice(1)) >= 1 && Number(client.slice(1)) <= 34)) throw new Error('malformed_result_record');
    if (broker && !(Number(broker.slice(1)) >= 1 && Number(broker.slice(1)) <= 38)) throw new Error('malformed_result_record');
    if (overflow === 'yes' && (client !== undefined || broker !== undefined)) throw new Error('malformed_result_record');
    if (broker !== undefined && client === undefined) throw new Error('malformed_result_record');
    if ((client !== undefined || broker !== undefined) &&
        (assertions === 'unavailable' || !assertions.split(',').includes('1988') || !assertions.split(',').includes('1346'))) {
      throw new Error('malformed_result_record');
    }
    if (phase !== undefined && (overflow !== 'no' || broker !== 'B15' || !assertions.split(',').includes('1988') || !assertions.split(',').includes('1346'))) throw new Error('malformed_result_record');
    return records[0];
  };
  const sourceBound = nestedReceiver.includes('wrapped_prefix = "        " + prefix') &&
    nestedReceiver.includes('if not line.startswith(wrapped_prefix):\n            reject("malformed_result_record")') &&
    nestedReceiver.includes('if len(records) != 1:\n        reject("malformed_result_record")') &&
    nestedReceiver.includes('full_record = prefix + records[0]') &&
    nestedReceiver.includes('len(full_record.encode("ascii")) > 128') &&
    nestedReceiver.includes('except UnicodeEncodeError:\n        reject("malformed_result_record")') &&
    nestedReceiver.includes('re.fullmatch(r"stage=test_nonzero exit=') &&
    nestedReceiver.includes('if exit_value.startswith("code:") and int(exit_value[5:]) > 255:\n        reject("malformed_result_record")') &&
    nestedReceiver.includes('if exit_value.startswith("signal:") and int(exit_value[7:]) > 64:\n        reject("malformed_result_record")') &&
    nestedReceiver.includes('any(value > 4800 for value in values) or len(values) != len(set(values))') &&
    nestedReceiver.includes('if client is not None and not 1 <= int(client[1:]) <= 34: reject("malformed_result_record")') &&
    nestedReceiver.includes('if broker is not None and not 1 <= int(broker[1:]) <= 38: reject("malformed_result_record")') &&
    nestedReceiver.includes('if overflow == "yes" and (client is not None or broker is not None): reject("malformed_result_record")') &&
    nestedReceiver.includes('if broker is not None and client is None: reject("malformed_result_record")') &&
    nestedReceiver.includes('if (client is not None or broker is not None) and ("1988" not in assertions.split(",") or "1346" not in assertions.split(",")): reject("malformed_result_record")') &&
    nestedReceiver.includes('(?: broker=(B[0-9]{2})(?: k=(K[1-3]))?)?') &&
    nestedReceiver.includes('exit_value, overflow, assertions, client, broker, phase = match.groups()');
  requireSource(sourceBound, 'Python raw diagnostic controls are not bound to the actual producer-framed parser predicates');
  requireSource(nestedReceiver.includes('if phase is not None and (overflow != "no" or client is None or broker != "B15"'),
    'Python optional-K phase must bind only to the actual bounded B15 client and original producer sites');

  const tailSignal64 = 'stage=test_nonzero exit=signal:64 overflow=no assertions=4799,4798,1988,1346 client=C34 broker=B38';
  const rawPositive = transcript(`${wrappedPrefix}${tailSignal64}\n`);
  const fullPositive = marker + tailSignal64;
  requireSource(Buffer.byteLength(fullPositive, 'ascii') === 127 && parseRaw(rawPositive) === tailSignal64,
    'raw Go eight-space producer transcript did not recover its exact bounded plain-wire tail');
  const tailK119 = 'stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C18 broker=B15 k=K2';
  const tailK123 = 'stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346,449 client=C18 broker=B15 k=K3';
  requireSource(Buffer.byteLength(marker + tailK119, 'ascii') === 119 && parseRaw(transcript(`${wrappedPrefix}${tailK119}\n`)) === tailK119 &&
    Buffer.byteLength(marker + tailK123, 'ascii') === 123 && parseRaw(transcript(`${wrappedPrefix}${tailK123}\n`)) === tailK123,
    'raw Go eight-space parser did not preserve correctly associated optional K values under the complete-record cap');
  const tail129 = 'stage=test_nonzero exit=unavailable overflow=no assertions=1988,1346,4799,4800 client=C34 broker=B38';
  const full129 = marker + tail129;
  requireSource(Buffer.byteLength(tail129, 'ascii') === 100 && Buffer.byteLength(full129, 'ascii') === 129 &&
    Buffer.byteLength(tail129, 'ascii') <= 128,
    'prefix-inclusive overflow negative lacks valid tail geometry');
  const mustReject = (sample) => {
    let failure;
    try { parseRaw(sample); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === 'malformed_result_record',
      'Python raw producer-framing equivalent accepted a malformed or out-of-bound transcript');
  };
  requireSource(parseRaw(transcript()) === null,
    'blank nested diagnostic absence invented a record');
  const cases = [
    transcript(`    ${marker}${tailSignal64}\n`),
    transcript(`            ${marker}${tailSignal64}\n`),
    transcript(`\t        ${marker}${tailSignal64}\n`),
    transcript(`${marker}${tailSignal64}\n`),
    transcript(`        FOREIGN ${marker}${tailSignal64}\n`),
    transcript(`${wrappedPrefix}${tailSignal64}\n${wrappedPrefix}${tailSignal64}\n`),
    transcript(`${wrappedPrefix}${tailSignal64}\n    ${marker}not-a-record\n`),
    transcript(`${wrappedPrefix}${tailSignal64}é\n`),
    transcript(`${wrappedPrefix}${tail129}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('signal:64', 'code:256')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('signal:64', 'signal:65')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('4799,4798,1988,1346', '4801,4798,1988,1346')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('4799,4798,1988,1346', '4799,4799,1988,1346')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('4799,4798,1988,1346', '4799,4798,1988,1346,247')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('C34', 'C35')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('B38', 'B39')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace(' client=C34 broker=B38', ' broker=B38')}\n`),
    transcript(`${wrappedPrefix}${tailSignal64.replace('overflow=no', 'overflow=yes')}\n`),
    transcript(`${wrappedPrefix}${tailK119.replace('broker=B15', 'broker=B14')}\n`),
    transcript(`${wrappedPrefix}${tailK119.replace('k=K2', 'k=K4')}\n`),
    transcript(`${wrappedPrefix}${tailK119.replace('overflow=no', 'overflow=yes')}\n`),
    transcript(`${wrappedPrefix}${tailK119.replace('assertions=1988,1346', 'assertions=1988')}\n`),
    transcript(`${wrappedPrefix}${tailK119.replace('client=C18 broker=B15 ', 'client=C18 ')}\n`),
  ];
  for (const sample of cases) mustReject(sample);
}

function nestedDiagnosticControls() {
  const nestedAssertionSites = (text) => {
    if (Buffer.byteLength(text, 'utf8') > 4096) return [];
    const lines = text.split('\n');
    const headerPrefix = '--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (';
    const header = /^--- FAIL: TestCheckpointObserverRouteComposedKernelFixture \([0-9]+(?:\.[0-9]+)?s\)$/;
    const run = '=== RUN   TestCheckpointObserverRouteComposedKernelFixture';
    let headers = 0;
    let collecting = true;
    let closed = false;
    let invalid = false;
    let runCount = 0;
    let failCount = 0;
    let sawAssertion = false;
    const sites = [];
    const seen = new Set();
    const source = '    checkpoint_local_observer_kernel_linux_test.go:';
    for (const line of lines) {
      if (line.startsWith('=== RUN')) {
        runCount += 1;
        if (runCount !== 1 || sawAssertion || closed || line !== run) invalid = true;
        continue;
      }
      if (line.startsWith('--- FAIL')) {
        headers += 1;
        if (headers !== 1 || !line.startsWith(headerPrefix) || !header.test(line) || closed) invalid = true;
        collecting = false;
        closed = true;
        continue;
      }
      if (line.startsWith('--- ')) {
        invalid = true;
        collecting = false;
        closed = true;
        continue;
      }
      if (line === 'FAIL') {
        failCount += 1;
        if (headers !== 1 || failCount !== 1) invalid = true;
        collecting = false;
        closed = true;
        continue;
      }
      if (!line.includes('checkpoint_local_observer_kernel_linux_test.go:')) continue;
      if (!collecting || !line.startsWith(source) || closed) { invalid = true; continue; }
      const record = line.slice(source.length);
      const separator = record.indexOf(': ');
      if (separator <= 0 || separator + 2 >= record.length) { invalid = true; continue; }
      const numberText = record.slice(0, separator);
      if (!/^[1-9][0-9]{0,3}$/.test(numberText)) { invalid = true; continue; }
      const value = Number(numberText);
      if (value > 4800 || seen.has(value) || sites.length === 4) { invalid = true; continue; }
      seen.add(value);
      sites.push(value);
      sawAssertion = true;
    }
    return headers === 1 && !invalid ? sites : [];
  };
  const rawPositive = '    checkpoint_local_observer_kernel_linux_test.go:245: controlled assertion\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\nFAIL';
  const withRun = `=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n${rawPositive}`;
  requireSource(JSON.stringify(nestedAssertionSites(rawPositive)) === '[245]' &&
    JSON.stringify(nestedAssertionSites(withRun)) === '[245]' &&
    nestedAssertionSites('    checkpoint_local_observer_kernel_linux_test.go:4801: out of range\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)').length === 0,
    'actual-order nested testing assertion controls did not identify only a bounded tagged Go assertion with optional selected RUN');
  const stackOnly = '\t/path/checkpoint_local_observer_kernel_linux_test.go:245 +0x20\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)';
  const forged = '    /tmp/checkpoint_local_observer_kernel_linux_test.go:245: forged path\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)';
  const noHeader = '    checkpoint_local_observer_kernel_linux_test.go:245: not testing output';
  requireSource(nestedAssertionSites(stackOnly).length === 0 && nestedAssertionSites(forged).length === 0 && nestedAssertionSites(noHeader).length === 0,
    'nested testing assertion negative controls admitted stack-only, forged-path, or headerless output');
  const four = [245, 246, 247, 248].map((n) => `    checkpoint_local_observer_kernel_linux_test.go:${n}: assertion`).join('\n') + '\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\n';
  const summaryThenLine = '--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\nFAIL\n    checkpoint_local_observer_kernel_linux_test.go:245: after summary';
  const summaryThenFailHeader = '    checkpoint_local_observer_kernel_linux_test.go:245: assertion\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\nFAIL\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\n';
  requireSource(nestedAssertionSites(summaryThenLine).length === 0 &&
    nestedAssertionSites(four + '--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.01s)\n').length === 0 &&
    nestedAssertionSites(four + '--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (bad)\n').length === 0 &&
    nestedAssertionSites(four + '--- FAIL: OtherTest (0.00s)\n').length === 0 &&
    nestedAssertionSites(four + '    checkpoint_local_observer_kernel_linux_test.go:245: duplicate\n').length === 0 &&
    nestedAssertionSites(four.slice(0, four.lastIndexOf('--- FAIL:')) + '    checkpoint_local_observer_kernel_linux_test.go:249: excess\n--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\n').length === 0 &&
    nestedAssertionSites(summaryThenFailHeader).length === 0 &&
    nestedAssertionSites('=== RUN   OtherTest\n' + rawPositive).length === 0 &&
    nestedAssertionSites(rawPositive.replace('--- FAIL:', '=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n--- FAIL:')).length === 0 &&
    nestedAssertionSites(withRun.replace('=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n', '=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n')).length === 0 &&
    nestedAssertionSites('--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)').length === 0 &&
    nestedAssertionSites('x'.repeat(4097)).length === 0,
    'full nested reducer controls failed summary closure, post-cap ambiguity, duplicate-site, or excess-site validation');
  const legacy = 'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=245';
  requireSource(boundedReceiverDiagnostic({ stdout: legacy, stderr: '' }) ===
    '\nremote receiver diagnostic: stage=test_nonzero nested_exit=code:1 nested_overflow=no nested_assertions=245',
    'legacy nested diagnostic without optional suffixes was not preserved');
  const k119 = 'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C18 broker=B15 k=K2';
  const k123 = 'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346,449 client=C18 broker=B15 k=K2';
  requireSource(Buffer.byteLength(k119.split('\n')[1], 'ascii') === 119 && Buffer.byteLength(k123.split('\n')[1], 'ascii') === 123 &&
    boundedReceiverDiagnostic({ stdout: k119, stderr: '' }) === '\nremote receiver diagnostic: stage=test_nonzero nested_exit=code:1 nested_overflow=no nested_assertions=1988,1346 client=C18 broker=B15 k=K2' &&
    boundedReceiverDiagnostic({ stdout: k123, stderr: '' }) === '\nremote receiver diagnostic: stage=test_nonzero nested_exit=code:1 nested_overflow=no nested_assertions=1988,1346,449 client=C18 broker=B15 k=K2',
    'Node receiver did not preserve the actual 119/123-byte finite-K positives');
  const positive = 'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=signal:64 overflow=no assertions=4799,4798,1988,1346 client=C34 broker=B38';
  const fullPrefix = 'REMOTE_OBSERVER_ROUTE_NESTED ';
  const overlongRecord = `${fullPrefix}stage=test_nonzero exit=unavailable overflow=no assertions=4799,4798,1988,1346 client=C34 broker=B38`;
  requireSource(Buffer.byteLength(fullPrefix + positive.split('\n')[1].slice(fullPrefix.length), 'ascii') === 127 &&
    Buffer.byteLength(overlongRecord, 'ascii') === 129 && boundedReceiverDiagnostic({ stdout: positive, stderr: '' }) ===
    '\nremote receiver diagnostic: stage=test_nonzero nested_exit=signal:64 nested_overflow=no nested_assertions=4799,4798,1988,1346 client=C34 broker=B38',
    'complete-prefix maximum-length nested positive or overlong full-record negative missed its exact ASCII boundary');
  requireSource(boundedReceiverDiagnostic({ stdout: `REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\n${overlongRecord}`, stderr: '' }) === '',
    'Node receiver accepted an overlong complete nested record including its prefix');
  const signal = 'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=signal:9 overflow=no assertions=unavailable';
  requireSource(boundedReceiverDiagnostic({ stdout: '', stderr: signal }) ===
    '\nremote receiver diagnostic: stage=test_nonzero nested_exit=signal:9 nested_overflow=no nested_assertions=unavailable',
    'nested diagnostic signal/unavailable control was not parsed canonically');
  const rejects = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=cleanup_root_identity\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:256 overflow=no assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=signal:65 overflow=no assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:01 overflow=no assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=maybe assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=4801',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=245,245',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=245,2107,2111,2115,2117',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=245\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=unavailable',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=/tmp/test.go:245 +0x20',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=unavailable overflow=no assertions=245 path=/tmp/key=secret',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C35 broker=B03',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C14 broker=B39',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 broker=B03',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=yes assertions=1988,1346 client=C14 broker=B03',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C14 broker=B03 path=/tmp/secret',
    k119.replace('broker=B15', 'broker=B14'),
    k119.replace(' client=C18', ''),
    k119.replace('1988,1346', '1988'),
    k119.replace('k=K2', 'k=K9'),
    k119.replace('overflow=no', 'overflow=yes'),
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_NESTED stage=test_nonzero exit=signal:64 overflow=no assertions=4799,4798,1988,1346 client=C34 broker=B15 k=K2',
  ];
  requireSource(rejects.every((sample) => boundedReceiverDiagnostic({ stdout: sample, stderr: '' }) === ''),
    'nested diagnostic negative controls accepted malformed, stack/path/message, duplicate, unbounded, or stage-mismatched data');
}

function receiverExceptionDiagnosticControls() {
  const positive = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception',
    'REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=317',
  ].join('\n');
  requireSource(boundedReceiverDiagnostic({ stdout: '', stderr: positive }) ===
    '\nremote receiver diagnostic: stage=receiver_exception exception_class=ValueError embedded_line=317',
    'receiver exception diagnostic positive control did not retain only the fixed class and bounded embedded line');
  const unavailable = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception',
    'REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=unavailable line=unavailable',
  ].join('\n');
  requireSource(boundedReceiverDiagnostic({ stdout: unavailable, stderr: '' }) ===
    '\nremote receiver diagnostic: stage=receiver_exception exception_class=unavailable embedded_line=unavailable',
    'receiver exception diagnostic unavailable-class control was not handled explicitly');
  const rejects = [
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=317\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=TypeError line=12',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=test_nonzero\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=317',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=CustomError line=317',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=0317',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=1001',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=317 path=/tmp/secret',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:317\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError line=317',
    'REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\nREMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=ValueError\nline=317',
  ];
  requireSource(rejects.every((sample) => boundedReceiverDiagnostic({ stdout: '', stderr: sample }) === ''),
    'receiver exception diagnostic negative controls accepted malformed, unknown, duplicate, injected, unbounded, or stage-inconsistent records');
}

function fixedFile(file, label) {
  let info;
  try { info = lstatSync(file); } catch { throw new Error(`${label} is unavailable at its fixed path`); }
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} is not a regular fixed-path file`);
  return info;
}

function windowsPathToWsl(value) {
  const result = invoke('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'wslpath', '-a', value], { timeout: 20_000 }, 'map private Windows test path into fixed Ubuntu WSL');
  const canonical = result.trim();
  if (!canonical.startsWith('/') || /[\r\n]/.test(canonical)) throw new Error('fixed WSL path conversion did not produce one canonical absolute path');
  return canonical;
}

function verifyWslUnitPrincipal() {
  const output = invoke('wsl.exe', ['-d', 'Ubuntu', '-u', 'berd', '--exec', '/usr/bin/id', '-u'],
    { timeout: 20_000 }, 'validate fixed unprivileged WSL principal');
  if (output.trim() !== '1000') throw new Error('fixed WSL principal berd did not report UID 1000');
}

function testRunPattern(expected) {
  const top = [...new Set(expected.map((name) => name.split('/')[0]))];
  return `^(${top.join('|')})$`;
}

function parseVerboseInventory(output, expected, description) {
  const runs = new Map(), passes = new Map(), runAt = new Map(), passAt = new Map(), failures = [], skips = [], malformed = [];
  for (const [index, line] of output.split(/\r?\n/).entries()) {
    const record = line.trimStart();
    if (record.startsWith('=== RUN')) {
      const match = record.match(/^=== RUN\s+(\S+)\s*$/);
      if (!match) malformed.push(line);
      else { runs.set(match[1], (runs.get(match[1]) ?? 0) + 1); runAt.set(match[1], index); }
    }
    if (/^--- (PASS|SKIP|FAIL)(?:\s|:)/.test(record)) {
      const match = record.match(/^--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/);
      if (!match) malformed.push(line);
      else if (match[1] === 'PASS') { passes.set(match[2], (passes.get(match[2]) ?? 0) + 1); passAt.set(match[2], index); }
      else if (match[1] === 'SKIP') skips.push(match[2]);
      else failures.push(match[2]);
    }
  }
  const expectedSet = new Set(expected);
  const missingRun = expected.filter((name) => runs.get(name) !== 1);
  const missingPass = expected.filter((name) => passes.get(name) !== 1);
  const unexpectedRun = [...runs.keys()].filter((name) => !expectedSet.has(name));
  const unexpectedPass = [...passes.keys()].filter((name) => !expectedSet.has(name));
  const reordered = expected.filter((name) => runAt.has(name) && passAt.has(name) && runAt.get(name) >= passAt.get(name));
  if (missingRun.length || missingPass.length || unexpectedRun.length || unexpectedPass.length || reordered.length || failures.length || skips.length || malformed.length) {
    throw new Error(`${description}: exact RUN/PASS inventory mismatch`);
  }
}

function verboseInventoryControls() {
  const expected = ['TestParent', 'TestParent/role', 'TestParent/role/leaf'];
  const positive = '=== RUN   TestParent\n=== RUN   TestParent/role\n=== RUN   TestParent/role/leaf\n    --- PASS: TestParent/role/leaf (0.00s)\n    --- PASS: TestParent/role (0.00s)\n--- PASS: TestParent (0.00s)\n';
  parseVerboseInventory(positive, expected, 'canonical indented child transcript');
  for (const [name, mutant] of [
    ['missing RUN', positive.replace('=== RUN   TestParent/role\n', '')],
    ['duplicate RUN', positive.replace('=== RUN   TestParent/role\n', '=== RUN   TestParent/role\n=== RUN   TestParent/role\n')],
    ['missing PASS', positive.replace('--- PASS: TestParent/role (0.00s)\n', '')],
    ['duplicate PASS', positive.replace('--- PASS: TestParent/role (0.00s)', '--- PASS: TestParent/role (0.00s)\n    --- PASS: TestParent/role (0.00s)')],
    ['reordered PASS', positive.replace('=== RUN   TestParent/role/leaf\n', '').replace('--- PASS: TestParent/role/leaf (0.00s)', '--- PASS: TestParent/role/leaf (0.00s)\n=== RUN   TestParent/role/leaf')],
    ['SKIP', positive.replace('--- PASS: TestParent/role (0.00s)', '--- SKIP: TestParent/role (0.00s)')],
    ['FAIL', positive.replace('--- PASS: TestParent/role (0.00s)', '--- FAIL: TestParent/role (0.00s)')],
    ['unknown nested name', positive.replace('TestParent/role/leaf', 'TestParent/role/other')],
    ['malformed event', positive.replace('--- PASS: TestParent/role (0.00s)', '--- PASS: TestParent/role')],
    ['PASS missing colon', `${positive}--- PASS TestParent/role (0.00s)\n`],
    ['SKIP missing colon', `${positive}    --- SKIP TestParent/role (0.00s)\n`],
    ['FAIL missing colon', `${positive}--- FAIL TestParent/role (0.00s)\n`],
    ['unrelated PASS missing colon', `${positive}--- PASS TestUnrelated (0.00s)\n`],
    ['RUN colon', `${positive}=== RUN: TestUnrelated\n`],
    ['malformed RUN shape', `${positive}=== RUN TestUnrelated extra\n`],
  ]) {
    let failure;
    try { parseVerboseInventory(mutant, expected, `negative control ${name}`); } catch (error) { failure = error; }
    if (!(failure instanceof Error) || failure.message !== `negative control ${name}: exact RUN/PASS inventory mismatch`) throw new Error(`verbose inventory parser did not reject ${name} at its inventory predicate`);
  }
}

function reduceReceiverEquivalentEvents(text) {
  const events = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const record = rawLine.trimStart();
    if (record.startsWith('=== RUN')) {
      const match = /^=== RUN\s+(\S+)$/.exec(record);
      if (!match) throw new Error('malformed_run_record');
      events.push(['RUN', match[1]]);
    } else if (/^--- (?:PASS|SKIP|FAIL)(?:\s|:)/.test(record)) {
      const match = /^--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)$/.exec(record);
      if (!match) throw new Error('malformed_result_record');
      events.push([match[1], match[2]]);
    }
  }
  return events;
}

function receiverParserControls() {
  const positive = '=== RUN   TestParent\n=== RUN   TestParent/role\n=== RUN   TestParent/role/leaf\n    --- PASS: TestParent/role/leaf (0.00s)\n    --- PASS: TestParent/role (0.00s)\n--- PASS: TestParent (0.00s)\n';
  const expected = [['RUN', 'TestParent'], ['RUN', 'TestParent/role'], ['RUN', 'TestParent/role/leaf'],
    ['PASS', 'TestParent/role/leaf'], ['PASS', 'TestParent/role'], ['PASS', 'TestParent']];
  const events = reduceReceiverEquivalentEvents(positive);
  requireSource(JSON.stringify(events) === JSON.stringify(expected), 'receiver-equivalent reducer rejected canonical indented parent/intermediate/leaf transcript');
  for (const [name, record, expectedError] of [
    ['malformed PASS', '--- PASS TestParent (0.00s)', 'malformed_result_record'],
    ['malformed SKIP', '    --- SKIP TestParent/role (0.00s)', 'malformed_result_record'],
    ['malformed FAIL', '--- FAIL TestParent/role/leaf (0.00s)', 'malformed_result_record'],
    ['unrelated malformed PASS', '--- PASS TestUnrelated (0.00s)', 'malformed_result_record'],
    ['malformed RUN colon', '=== RUN: TestUnrelated', 'malformed_run_record'],
    ['malformed RUN shape', '=== RUN TestUnrelated extra', 'malformed_run_record'],
  ]) {
    let failure;
    try { reduceReceiverEquivalentEvents(`${positive}${record}\n`); } catch (error) { failure = error; }
    requireSource(failure instanceof Error && failure.message === expectedError, `receiver-equivalent reducer missed intended ${name} shape guard`);
  }
}

function strictComposedTranscript(text) {
  const events = [];
  for (const [index, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trimStart();
    if (line.startsWith('=== RUN')) {
      const match = /^=== RUN\s+(\S+)\s*$/.exec(line);
      if (!match) throw new Error(`malformed kernel RUN record at line ${index + 1}`);
      events.push(`RUN:${match[1]}`);
    } else if (/^--- (PASS|SKIP|FAIL)(?:\s|:)/.test(line)) {
      const match = /^--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)\s*$/.exec(line);
      if (!match) throw new Error(`malformed kernel result record at line ${index + 1}`);
      events.push(`${match[1]}:${match[2]}`);
    }
  }
  const want = ['RUN:TestCheckpointObserverRouteComposedKernelFixture', 'PASS:TestCheckpointObserverRouteComposedKernelFixture'];
  if (events.length !== want.length || events.some((event, index) => event !== want[index])) throw new Error('kernel RUN/PASS inventory is not exact and ordered');
  const markers = [
    'CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS',
    'CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS',
    'CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS',
    'CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS',
    'CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2',
    'CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY',
    'CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS',
  ];
  let previous = -1;
  for (const marker of markers) {
    if (text.split(marker).length !== 2) throw new Error('composed child marker is missing or duplicated');
    const current = text.indexOf(marker);
    if (current <= previous) throw new Error('composed child markers are reordered');
    previous = current;
  }
}

function composedTranscriptControls() {
  const good = '=== RUN   TestCheckpointObserverRouteComposedKernelFixture\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS\nCHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS\nCHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS\nCHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2\nCHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY\nCHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS\n--- PASS: TestCheckpointObserverRouteComposedKernelFixture (1.00s)\n';
  strictComposedTranscript(good);
  for (const [label, mutant] of [
    ['missing child RUN', good.replace('=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n', '')],
    ['duplicate parent RUN', good.replace('=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n', '=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n')],
    ['missing parent PASS', good.replace('--- PASS: TestCheckpointObserverRouteComposedKernelFixture (1.00s)\n', '')],
    ['duplicate parent PASS', good.replace('--- PASS:', '--- PASS:') + '--- PASS: TestCheckpointObserverRouteComposedKernelFixture (1.00s)\n'],
    ['missing parent-death marker', good.replace('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS\n', '')],
    ['duplicate outside sentinel marker', good + 'CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS\n'],
    ['reordered markers', good.replace('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS\nCHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2', 'CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2\nCHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS')],
    ['SKIP', good.replace('--- PASS:', '--- SKIP:')],
    ['FAIL', good.replace('--- PASS:', '--- FAIL:')],
    ['unknown nested RUN', good.replace('--- PASS: TestCheckpointObserverRouteComposedKernelFixture', '=== RUN   unexpected\n--- PASS: TestCheckpointObserverRouteComposedKernelFixture')],
    ['malformed result', good.replace('(1.00s)', '(unknown)')],
  ]) {
    let rejected = false;
    try { strictComposedTranscript(mutant); } catch { rejected = true; }
    if (!rejected) throw new Error(`strict kernel transcript accepted ${label}`);
  }
}

function captureFilePin(file) {
  const info = lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.size <= 0) throw new Error('private compiled test output is not a regular nonempty file');
  return { dev: info.dev, ino: info.ino, size: info.size };
}

function removeExactScratch(scratch, rootPin, pins) {
  const current = lstatSync(scratch);
  if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== rootPin.dev || current.ino !== rootPin.ino) {
    throw new Error('private compiler scratch identity changed; preserving it');
  }
  const allowed = new Set(pins.keys());
  const entries = readdirSync(scratch);
  if (entries.some((name) => !allowed.has(name))) throw new Error('private compiler scratch has an unknown entry; preserving it');
  for (const name of entries) {
    const pin = pins.get(name);
    if (!pin) throw new Error('private compiler scratch entry lacks a held pin; preserving it');
    const file = path.join(scratch, name);
    if (pin.kind === 'compiler-tree') verifyCompilerTree(file, pin);
    else {
      const info = lstatSync(file);
      if (!info.isFile() || info.isSymbolicLink() || info.dev !== pin.dev || info.ino !== pin.ino || info.size !== pin.size) {
        throw new Error('private compiler output identity changed; preserving it');
      }
    }
  }
  for (const name of entries) {
    const file = path.join(scratch, name);
    const pin = pins.get(name);
    if (pin.kind === 'compiler-tree') removeCompilerTree(file, pin);
    else unlinkSync(file);
  }
  rmdirSync(scratch);
}

function captureCompilerTree(directory, originalRoot = null) {
  const rootInfo = lstatSync(directory);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || !Number.isSafeInteger(rootInfo.nlink) || rootInfo.nlink < 1) throw new Error('compiler cache/temp root is not a held directory');
  if (originalRoot && (rootInfo.dev !== originalRoot.dev || rootInfo.ino !== originalRoot.ino || rootInfo.mode !== originalRoot.mode)) {
    throw new Error('compiler cache/temp root no longer matches its immediately registered creation identity; preserving scratch');
  }
  const entries = [];
  let totalBytes = 0;
  function visit(current, relative) {
    const names = readdirSync(current).sort();
    for (const name of names) {
      if (name === '.' || name === '..' || name.includes('/') || name.includes('\\')) throw new Error('compiler cache/temp contains a noncanonical entry');
      const child = path.join(current, name), childRelative = relative ? `${relative}/${name}` : name;
      const info = lstatSync(child);
      if (info.isSymbolicLink()) throw new Error('compiler cache/temp contains a symbolic link; preserving scratch');
      if (info.isDirectory()) {
        if (!Number.isSafeInteger(info.nlink) || info.nlink < 1) throw new Error('compiler cache/temp directory link count is invalid');
        entries.push({ relative: childRelative, kind: 'directory', dev: info.dev, ino: info.ino, mode: info.mode, nlink: info.nlink });
        visit(child, childRelative);
      } else if (info.isFile() && info.nlink === 1) {
        totalBytes += info.size;
        if (totalBytes > 2 * 1024 * 1024 * 1024) throw new Error('compiler cache/temp exceeded its explicit two-GiB cleanup bound');
        entries.push({ relative: childRelative, kind: 'file', dev: info.dev, ino: info.ino, mode: info.mode, nlink: info.nlink, size: info.size });
      } else throw new Error('compiler cache/temp contains an unexpected inode type or link count; preserving scratch');
      if (entries.length > 200000) throw new Error('compiler cache/temp exceeded its explicit entry bound');
    }
  }
  visit(directory, '');
  return { kind: 'compiler-tree', dev: rootInfo.dev, ino: rootInfo.ino, mode: rootInfo.mode, nlink: rootInfo.nlink, entries, totalBytes };
}

function createCompilerTrees(scratch, rootPin, pins) {
  const root = lstatSync(scratch);
  if (!root.isDirectory() || root.isSymbolicLink() || root.dev !== rootPin.dev || root.ino !== rootPin.ino) {
    throw new Error('private compiler scratch root changed before cache/temp creation; preserving it');
  }
  for (const name of ['go-cache', 'go-tmp']) {
    if (pins.has(name) || readdirSync(scratch).some((entry) => !pins.has(entry))) {
      throw new Error('private compiler scratch has a duplicate or unknown entry before cache/temp creation; preserving it');
    }
    const directory = path.join(scratch, name);
    mkdirSync(directory, { mode: 0o700 });
    const info = lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`new ${name} root is not an exclusive directory; preserving scratch`);
    const ownerPin = { kind: 'compiler-tree', dev: info.dev, ino: info.ino, mode: info.mode, nlink: info.nlink, entries: [], totalBytes: 0 };
    pins.set(name, ownerPin);
    const captured = captureCompilerTree(directory, ownerPin);
    if (captured.entries.length !== 0 || captured.totalBytes !== 0) throw new Error(`new ${name} root was not empty at creation; preserving scratch`);
    pins.set(name, captured);
  }
}

function verifyCompilerRoots(scratch, pins) {
  for (const name of ['go-cache', 'go-tmp']) {
    const pin = pins.get(name), directory = path.join(scratch, name), info = lstatSync(directory);
    if (!pin || pin.kind !== 'compiler-tree' || !info.isDirectory() || info.isSymbolicLink() || info.dev !== pin.dev || info.ino !== pin.ino || info.mode !== pin.mode) {
      throw new Error(`compiler ${name} root changed from its registered creation identity; preserving scratch`);
    }
  }
}

function verifyCompilerTree(directory, pin) {
  const rootInfo = lstatSync(directory);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || rootInfo.dev !== pin.dev || rootInfo.ino !== pin.ino || rootInfo.mode !== pin.mode || rootInfo.nlink !== pin.nlink) {
    throw new Error('compiler cache/temp root identity changed; preserving scratch');
  }
  const actual = captureCompilerTree(directory);
  if (actual.totalBytes !== pin.totalBytes || actual.entries.length !== pin.entries.length || actual.entries.some((entry, index) => {
    const want = pin.entries[index];
    return !want || Object.keys(want).some((key) => entry[key] !== want[key]);
  })) throw new Error('compiler cache/temp contents changed after final identity pin; preserving scratch');
}

function removeCompilerTree(directory, pin) {
  verifyCompilerTree(directory, pin);
  const directories = pin.entries.filter((entry) => entry.kind === 'directory').sort((a, b) => b.relative.split('/').length - a.relative.split('/').length);
  for (const entry of pin.entries) if (entry.kind === 'file') unlinkSync(path.join(directory, ...entry.relative.split('/')));
  for (const entry of directories) rmdirSync(path.join(directory, ...entry.relative.split('/')));
  rmdirSync(directory);
}

function compileLinuxTest(go, packagePath, tags, output, timeout = 180_000) {
  const scratch = path.dirname(output);
  const environment = {
    PATH: `${fixedGoBin};C:/Windows/System32`, SystemRoot: 'C:/Windows', TEMP: scratch, TMP: scratch,
    GOTOOLCHAIN: 'local', GOENV: 'off', GOFLAGS: '', GOCACHE: path.join(scratch, 'go-cache'), GOTMPDIR: path.join(scratch, 'go-tmp'),
    GOMODCACHE: 'C:/Users/Sasha/go/pkg/mod', GOPROXY: 'off', GOSUMDB: 'off', GONOSUMDB: '*',
    GOOS: 'linux', GOARCH: 'amd64', GOAMD64: 'v1', CGO_ENABLED: '0',
  };
  invoke(go, ['test', '-c', ...(tags ? ['-tags', tags] : []), '-o', output, packagePath], { timeout, maxBuffer: 8 * 1024 * 1024, diagnosticLimit: 4096, env: environment }, `compile fixed Linux test image for ${packagePath}`);
  return captureFilePin(output);
}

function runUnit() {
  if (process.platform !== 'win32') throw new Error('--unit is fixed to the Windows cached toolchain plus Ubuntu WSL berd UID 1000 transport');
  fixedFile(fixedGo, 'cached Go 1.23.4 toolchain');
  verifyWslUnitPrincipal();
  const scratch = mkdtempSync(path.join(tmpdir(), 'checkpoint-observer-route-unit-'));
  const rootInfo = lstatSync(scratch);
  const rootPin = { dev: rootInfo.dev, ino: rootInfo.ino };
  const pins = new Map();
  let confirmed = false;
  try {
    createCompilerTrees(scratch, rootPin, pins);
    for (const [index, [pkg, expected]] of Object.entries(unitInventory).entries()) {
      const name = index === 0 ? 'observer-linux.test' : 'nodeagent-linux.test';
      const binary = path.join(scratch, name);
      verifyCompilerRoots(scratch, pins);
      pins.set(name, compileLinuxTest(fixedGo, pkg, '', binary, 180_000));
      const linuxBinary = windowsPathToWsl(binary);
      invoke('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '--exec', 'chmod', '+x', linuxBinary], { timeout: 20_000 }, 'publish private Linux unit binary for WSL execution');
      const pattern = testRunPattern(expected);
      const output = invoke('wsl.exe', ['-d', 'Ubuntu', '-u', 'berd', '--exec', '/usr/bin/env', '-i', 'PATH=/usr/bin:/bin', 'HOME=/tmp', 'LANG=C', 'LC_ALL=C', linuxBinary,
        '-test.run=' + pattern, '-test.count=1', '-test.timeout=60s', '-test.v'], { timeout: 90_000, maxBuffer: 8 * 1024 * 1024 }, `unprivileged WSL unit tests for ${pkg}`);
      parseVerboseInventory(output, expected, `unprivileged WSL unit tests for ${pkg}`);
    }
    for (const name of ['go-cache', 'go-tmp']) pins.set(name, captureCompilerTree(path.join(scratch, name), pins.get(name)));
    confirmed = true;
  } finally {
    if (confirmed) removeExactScratch(scratch, rootPin, pins);
    else process.stderr.write('unit verification failed; preserving private compiler workspace because cleanup is unconfirmed\n');
  }
}

const routeProxmoxReceiver = String.raw`import ctypes, hashlib, os, re, selectors, signal, stat, subprocess, sys, tempfile, time
EXPECTED_PIDNS = 4026531836
MAX_BINARY = 256 * 1024 * 1024
MAX_OUTPUT = 2 * 1024 * 1024
MAX_SECONDS = 125
ROOT = None
SAFE_EXCEPTION_CLASSES = {
    AssertionError: "AssertionError", AttributeError: "AttributeError", IndexError: "IndexError",
    KeyError: "KeyError", MemoryError: "MemoryError", OSError: "OSError", OverflowError: "OverflowError",
    RuntimeError: "RuntimeError", TimeoutError: "TimeoutError", TypeError: "TypeError",
    UnicodeError: "UnicodeError", ValueError: "ValueError",
}
def fail(stage, source_locations=(), nested_diagnostic=None):
    sys.stderr.write("REMOTE_OBSERVER_ROUTE_FAILURE stage=%s\n" % stage)
    if stage == "test_nonzero":
        for line_number in source_locations[:16]:
            if type(line_number) is int and 1 <= line_number <= 4800:
                sys.stderr.write("REMOTE_OBSERVER_ROUTE_FAILURE_SOURCE checkpoint_local_observer_kernel_linux_test.go:%d\n" % line_number)
        if nested_diagnostic is not None:
            sys.stderr.write("REMOTE_OBSERVER_ROUTE_NESTED %s\n" % nested_diagnostic)
    sys.stderr.flush()
    raise SystemExit(1)
def failure_source_locations(text):
    locations = []
    seen = set()
    for line in text.splitlines():
        match = re.fullmatch(r"[ \t]*checkpoint_local_observer_kernel_linux_test\.go:([1-9][0-9]{0,3})(?=[: \t]|$).*", line)
        if not match:
            continue
        line_number = int(match.group(1))
        if line_number > 4800 or line_number in seen:
            continue
        seen.add(line_number)
        locations.append(line_number)
        if len(locations) == 16:
            break
    return locations
def failure_nested_diagnostic(text, *, reject=fail):
    prefix = "REMOTE_OBSERVER_ROUTE_NESTED "
    wrapped_prefix = "        " + prefix
    records = []
    for line in text.splitlines():
        if "REMOTE_OBSERVER_ROUTE_NESTED" not in line:
            continue
        if not line.startswith(wrapped_prefix):
            reject("malformed_result_record")
        records.append(line[len(wrapped_prefix):])
    if not records:
        return None
    if len(records) != 1:
        reject("malformed_result_record")
    full_record = prefix + records[0]
    try:
        if len(full_record.encode("ascii")) > 128:
            reject("malformed_result_record")
    except UnicodeEncodeError:
        reject("malformed_result_record")
    match = re.fullmatch(r"stage=test_nonzero exit=(unavailable|code:[1-9][0-9]{0,2}|signal:[1-9][0-9]?) overflow=(yes|no) assertions=(unavailable|[1-9][0-9]{0,3}(?:,[1-9][0-9]{0,3}){0,3})(?: client=(C[0-9]{2})(?: broker=(B[0-9]{2})(?: k=(K[1-3]))?)?)?", records[0])
    if not match:
        reject("malformed_result_record")
    exit_value, overflow, assertions, client, broker, phase = match.groups()
    if exit_value.startswith("code:") and int(exit_value[5:]) > 255:
        reject("malformed_result_record")
    if exit_value.startswith("signal:") and int(exit_value[7:]) > 64:
        reject("malformed_result_record")
    if assertions != "unavailable":
        values = [int(value) for value in assertions.split(",")]
        if any(value > 4800 for value in values) or len(values) != len(set(values)):
            reject("malformed_result_record")
    if client is not None and not 1 <= int(client[1:]) <= 34: reject("malformed_result_record")
    if broker is not None and not 1 <= int(broker[1:]) <= 38: reject("malformed_result_record")
    if overflow == "yes" and (client is not None or broker is not None): reject("malformed_result_record")
    if broker is not None and client is None: reject("malformed_result_record")
    if (client is not None or broker is not None) and ("1988" not in assertions.split(",") or "1346" not in assertions.split(",")): reject("malformed_result_record")
    if phase is not None and (overflow != "no" or client is None or broker != "B15" or "1988" not in assertions.split(",") or "1346" not in assertions.split(",")): reject("malformed_result_record")
    return "stage=test_nonzero exit=%s overflow=%s assertions=%s%s%s%s" % (exit_value, overflow, assertions, " client=" + client if client is not None else "", " broker=" + broker if broker is not None else "", " k=" + phase if phase is not None else "")
def failure_nested_diagnostic_controls():
    class _ExpectedNestedDiagnosticReject(Exception):
        pass
    reject_sentinel = _ExpectedNestedDiagnosticReject()
    def _reject(stage):
        if stage != "malformed_result_record": raise RuntimeError("nested parser used an unexpected rejection stage")
        raise reject_sentinel
    prefix = "REMOTE_OBSERVER_ROUTE_NESTED "
    run_record = "=== RUN   TestCheckpointObserverRouteComposedKernelFixture\n"
    outer_failure = "    checkpoint_local_observer_kernel_linux_test.go:625: child test failed\n"
    failure_record = "--- FAIL: TestCheckpointObserverRouteComposedKernelFixture (0.00s)\n"
    def transcript(nested=""):
        return run_record + outer_failure + nested + failure_record
    tail_signal64 = "stage=test_nonzero exit=signal:64 overflow=no assertions=4799,4798,1988,1346 client=C34 broker=B38"
    raw_positive = transcript("        " + prefix + tail_signal64 + "\n")
    if len((prefix + tail_signal64).encode("ascii")) != 127:
        raise RuntimeError("raw nested positive length geometry changed")
    expected = failure_nested_diagnostic(raw_positive)
    if expected != tail_signal64:
        raise RuntimeError("raw nested producer transcript did not recover its exact wire tail")
    tail_k119 = "stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346 client=C18 broker=B15 k=K2"
    raw_k119 = transcript("        " + prefix + tail_k119 + "\n")
    if len((prefix + tail_k119).encode("ascii")) != 119 or failure_nested_diagnostic(raw_k119) != tail_k119:
        raise RuntimeError("optional K maximum proven-fitting broker/client record was not accepted at 119 ASCII bytes")
    tail_k123 = "stage=test_nonzero exit=code:1 overflow=no assertions=1988,1346,449 client=C18 broker=B15 k=K3"
    raw_k123 = transcript("        " + prefix + tail_k123 + "\n")
    if len((prefix + tail_k123).encode("ascii")) != 123 or failure_nested_diagnostic(raw_k123) != tail_k123:
        raise RuntimeError("optional K associated broker record was not accepted at 123 ASCII bytes")
    blank = transcript()
    if failure_nested_diagnostic(blank) is not None:
        raise RuntimeError("blank nested diagnostic absence invented a record")
    def expect_reject(raw):
        try:
            failure_nested_diagnostic(raw, reject=_reject)
        except _ExpectedNestedDiagnosticReject as error:
            if error is not reject_sentinel:
                raise RuntimeError("nested parser raised a different rejection sentinel")
            return
        raise RuntimeError("nested parser accepted a malformed control transcript")
    wrapped = "        " + prefix
    tail129 = "stage=test_nonzero exit=unavailable overflow=no assertions=1988,1346,4799,4800 client=C34 broker=B38"
    if len(tail129.encode("ascii")) != 100 or len((prefix + tail129).encode("ascii")) != 129:
        raise RuntimeError("raw nested over-bound control geometry changed")
    malformed = [
        "    " + prefix + tail_signal64 + "\n",
        "            " + prefix + tail_signal64 + "\n",
        "\t        " + prefix + tail_signal64 + "\n",
        prefix + tail_signal64 + "\n",
        "        FOREIGN " + prefix + tail_signal64 + "\n",
        "        " + prefix + tail_signal64 + "\n        " + prefix + tail_signal64 + "\n",
        "        " + prefix + tail_signal64 + "\n    " + prefix + "not-a-record\n",
        wrapped + tail_signal64 + "é\n",
        wrapped + tail129 + "\n",
        wrapped + tail_signal64.replace("signal:64", "code:256") + "\n",
        wrapped + tail_signal64.replace("signal:64", "signal:65") + "\n",
        wrapped + tail_signal64.replace("4799,4798,1988,1346", "4801,4798,1988,1346") + "\n",
        wrapped + tail_signal64.replace("4799,4798,1988,1346", "4799,4799,1988,1346") + "\n",
        wrapped + tail_signal64.replace("4799,4798,1988,1346", "4799,4798,1988,1346,247") + "\n",
        wrapped + tail_signal64.replace("C34", "C35") + "\n",
        wrapped + tail_signal64.replace("B38", "B39") + "\n",
        wrapped + tail_signal64.replace(" client=C34 broker=B38", " broker=B38") + "\n",
        wrapped + tail_signal64.replace("overflow=no", "overflow=yes") + "\n",
        wrapped + tail_k119.replace("broker=B15", "broker=B14") + "\n",
        wrapped + tail_k119.replace(" client=C18", "") + "\n",
        wrapped + tail_k119.replace("1988,1346", "1988") + "\n",
        wrapped + tail_k119.replace("k=K2", "k=K9") + "\n",
        wrapped + tail_k119.replace("overflow=no", "overflow=yes") + "\n",
        wrapped + "stage=test_nonzero exit=unavailable overflow=no assertions=1988,1346,4799,4800 client=C34 broker=B38 k=K2\n",
    ]
    for raw in malformed:
        expect_reject(transcript(raw))
def embedded_exception_line(error):
    traceback = error.__traceback__
    walked = 0
    selected = None
    while traceback is not None and walked < 16:
        frame = traceback.tb_frame
        line_number = traceback.tb_lineno
        if frame.f_code.co_filename == "<string>" and type(line_number) is int and 1 <= line_number <= 1000:
            selected = line_number
        traceback = traceback.tb_next
        walked += 1
    return selected
def fail_exception(error):
    class_name = SAFE_EXCEPTION_CLASSES.get(type(error), "unavailable")
    line_number = embedded_exception_line(error)
    line_text = str(line_number) if line_number is not None else "unavailable"
    sys.stderr.write("REMOTE_OBSERVER_ROUTE_FAILURE stage=receiver_exception\n")
    sys.stderr.write("REMOTE_OBSERVER_ROUTE_FAILURE_EXCEPTION class=%s line=%s\n" % (class_name, line_text))
    sys.stderr.flush()
    raise SystemExit(1)
def initial_namespace():
    if os.geteuid() != 0 or os.uname().sysname != "Linux" or os.uname().machine != "x86_64":
        fail("host_identity")
    if os.stat("/proc/self/ns/pid").st_ino != EXPECTED_PIDNS or os.stat("/proc/1/ns/pid").st_ino != EXPECTED_PIDNS:
        fail("initial_pid_namespace")
def digest_fd(fd):
    value = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 65536, offset)
        if not block:
            break
        offset += len(block)
        if offset > MAX_BINARY:
            fail("binary_bound")
        value.update(block)
    return value.hexdigest(), offset
def pin_upload(fd, name, expected_size, expected_sha):
    held = os.fstat(fd)
    named = os.stat(name, dir_fd=upload_fd, follow_symlinks=False)
    digest, size = digest_fd(fd)
    header = os.pread(fd, 20, 0)
    if not stat.S_ISREG(held.st_mode) or held.st_uid != 0 or held.st_nlink != 1 or stat.S_IMODE(held.st_mode) != 0o700:
        fail("upload_file_identity")
    if (held.st_dev, held.st_ino, held.st_size) != (named.st_dev, named.st_ino, named.st_size) or size != expected_size or digest != expected_sha:
        fail("upload_bytes_or_path")
    if len(header) != 20 or header[:4] != b"\x7fELF" or header[4] != 2 or header[5] != 1 or int.from_bytes(header[18:20], "little") != 62:
        fail("upload_elf_identity")
    return (held.st_dev, held.st_ino, held.st_size, digest)
def verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root):
    root_now = os.fstat(upload_fd)
    root_named = os.stat(os.path.basename(root), dir_fd=tmp_fd, follow_symlinks=False)
    tmp_now = os.fstat(tmp_fd)
    tmp_named = os.stat("/tmp", follow_symlinks=False)
    if (root_now.st_dev, root_now.st_ino) != held_root[:2] or (root_named.st_dev, root_named.st_ino) != held_root[:2] or root_now.st_uid != 0 or stat.S_IMODE(root_now.st_mode) != 0o700:
        fail("upload_root")
    if (tmp_now.st_dev, tmp_now.st_ino) != held_tmp[:2] or (tmp_named.st_dev, tmp_named.st_ino) != held_tmp[:2] or tmp_now.st_uid != 0 or stat.S_IMODE(tmp_now.st_mode) & 0o777 != 0o777 or not tmp_now.st_mode & stat.S_ISVTX:
        fail("tmp_identity")
def handoff_exec_uploads(specs, files, root, tmp_fd, held_tmp, upload_fd, held_root):
    verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)
    for name, expected_size, expected_sha in specs:
        writer_fd, original_pin = files[name]
        if pin_upload(writer_fd, name, expected_size, expected_sha) != original_pin:
            fail("upload_file_identity")
        read_fd = None
        adopted = False
        try:
            read_fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=upload_fd)
            read_pin = pin_upload(read_fd, name, expected_size, expected_sha)
            writer = os.fstat(writer_fd)
            reader = os.fstat(read_fd)
            if read_pin != original_pin or (writer.st_dev, writer.st_ino, writer.st_size) != (reader.st_dev, reader.st_ino, reader.st_size):
                fail("upload_file_identity")
            files[name] = (read_fd, read_pin)
            adopted = True
            os.close(writer_fd)
        except BaseException as failure:
            if read_fd is not None and not adopted:
                try:
                    os.close(read_fd)
                except BaseException as close_error:
                    raise RuntimeError("unadopted read descriptor close was uncertain") from close_error
            raise failure
    verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)
    for name, expected_size, expected_sha in specs:
        fd, pin = files[name]
        if pin_upload(fd, name, expected_size, expected_sha) != pin:
            fail("upload_file_identity")
    verify_upload_root(root, tmp_fd, held_tmp, upload_fd, held_root)
def exact_cleanup(root, tmp_fd, held_tmp, upload_fd, held_root, files):
    names = sorted(os.listdir(upload_fd))
    if names != sorted(files.keys()):
        fail("cleanup_unexpected_entries")
    for name, (fd, pin) in files.items():
        current = os.fstat(fd)
        named = os.stat(name, dir_fd=upload_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_size) != pin[:3] or (named.st_dev, named.st_ino, named.st_size) != pin[:3] or current.st_nlink != 1 or current.st_uid != 0:
            fail("cleanup_file_identity")
    root_now = os.fstat(upload_fd)
    root_named = os.stat(os.path.basename(root), dir_fd=tmp_fd, follow_symlinks=False)
    tmp_now = os.fstat(tmp_fd)
    tmp_named = os.stat("/tmp", follow_symlinks=False)
    if (root_now.st_dev, root_now.st_ino) != held_root[:2] or (root_named.st_dev, root_named.st_ino) != held_root[:2] or root_now.st_uid != 0 or stat.S_IMODE(root_now.st_mode) != 0o700:
        fail("cleanup_root_identity")
    if (tmp_now.st_dev, tmp_now.st_ino) != held_tmp[:2] or (tmp_named.st_dev, tmp_named.st_ino) != held_tmp[:2] or tmp_now.st_uid != 0 or stat.S_IMODE(tmp_now.st_mode) & 0o777 != 0o777 or not tmp_now.st_mode & stat.S_ISVTX:
        fail("cleanup_tmp_identity")
    for name in files:
        os.unlink(name, dir_fd=upload_fd)
    if os.listdir(upload_fd):
        fail("cleanup_file_absence")
    for fd, _ in files.values():
        os.close(fd)
    os.close(upload_fd)
    os.rmdir(os.path.basename(root), dir_fd=tmp_fd)
    try:
        os.stat(os.path.basename(root), dir_fd=tmp_fd, follow_symlinks=False)
        fail("cleanup_root_absence")
    except FileNotFoundError:
        pass
    if (os.fstat(tmp_fd).st_dev, os.fstat(tmp_fd).st_ino) != held_tmp[:2]:
        fail("cleanup_tmp_recheck")
    os.close(tmp_fd)
def main():
    global ROOT, upload_fd
    failure_nested_diagnostic_controls()
    initial_namespace()
    if len(sys.argv) != 5 or not sys.argv[1].isdigit() or not sys.argv[3].isdigit() or len(sys.argv[2]) != 64 or len(sys.argv[4]) != 64:
        fail("arguments")
    specs = [("checkpoint-observer-host.test", int(sys.argv[1]), sys.argv[2]), ("nodeagent.test", int(sys.argv[3]), sys.argv[4])]
    if any(size <= 0 or size > MAX_BINARY for _, size, _ in specs) or sum(size for _, size, _ in specs) > 2 * MAX_BINARY:
        fail("binary_bound")
    tmp_stat = os.stat("/tmp", follow_symlinks=False)
    if not stat.S_ISDIR(tmp_stat.st_mode) or tmp_stat.st_uid != 0 or stat.S_IMODE(tmp_stat.st_mode) & 0o777 != 0o777 or not tmp_stat.st_mode & stat.S_ISVTX:
        fail("tmp_preflight")
    tmp_fd = os.open("/tmp", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held_tmp_stat = os.fstat(tmp_fd)
    held_tmp = (held_tmp_stat.st_dev, held_tmp_stat.st_ino)
    if (held_tmp_stat.st_dev, held_tmp_stat.st_ino) != (tmp_stat.st_dev, tmp_stat.st_ino):
        fail("tmp_identity")
    ROOT = tempfile.mkdtemp(prefix="checkpoint-observer-route-upload-", dir="/tmp")
    root_stat = os.stat(ROOT, follow_symlinks=False)
    upload_fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    held_root_stat = os.fstat(upload_fd)
    held_root = (held_root_stat.st_dev, held_root_stat.st_ino)
    if (held_root_stat.st_dev, held_root_stat.st_ino) != (root_stat.st_dev, root_stat.st_ino) or held_root_stat.st_uid != 0 or stat.S_IMODE(held_root_stat.st_mode) != 0o700:
        fail("upload_root")
    files = {}
    try:
        for name, size, expected_sha in specs:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o700, dir_fd=upload_fd)
            created = os.fstat(fd)
            files[name] = (fd, (created.st_dev, created.st_ino, created.st_size, ""))
            digest = hashlib.sha256()
            remaining = size
            first = bytearray()
            while remaining:
                block = sys.stdin.buffer.read(min(65536, remaining))
                if not block:
                    fail("upload_truncated")
                remaining -= len(block)
                digest.update(block)
                if len(first) < 20:
                    first.extend(block[:20-len(first)])
                view = memoryview(block)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        fail("upload_write")
                    view = view[count:]
            if digest.hexdigest() != expected_sha or len(first) != 20 or bytes(first[:4]) != b"\x7fELF" or first[4] != 2 or first[5] != 1 or int.from_bytes(first[18:20], "little") != 62:
                fail("upload_digest_or_elf")
            os.fsync(fd)
            pin = pin_upload(fd, name, size, expected_sha)
            files[name] = (fd, pin)
        if sys.stdin.buffer.read(1):
            fail("upload_trailing_bytes")
        handoff_exec_uploads(specs, files, ROOT, tmp_fd, held_tmp, upload_fd, held_root)
        host_path = os.path.join(ROOT, "checkpoint-observer-host.test")
        node_path = os.path.join(ROOT, "nodeagent.test")
        env = {"PATH": "/usr/bin:/bin", "HOME": "/root", "TMPDIR": "/tmp", "LANG": "C", "LC_ALL": "C",
               "CHECKPOINT_OBSERVER_ROUTE_KERNEL": "1", "CHECKPOINT_OBSERVER_ROUTE_HOST_TEST_BINARY": host_path}
        receiver_pid = os.getpid()
        def set_receiver_parent_death():
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != receiver_pid:
                os._exit(125)
        proc = subprocess.Popen([node_path, "-test.run=^TestCheckpointObserverRouteComposedKernelFixture$", "-test.count=1", "-test.timeout=110s", "-test.v"],
                                cwd="/tmp", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True, start_new_session=True, preexec_fn=set_receiver_parent_death)
        pidfd = None
        output = bytearray()
        selector = None
        try:
            pidfd = os.pidfd_open(proc.pid, 0)
            st = os.stat("/proc/%d/exe" % proc.pid)
            node_st = os.fstat(files["nodeagent.test"][0])
            if (st.st_dev, st.st_ino) != (node_st.st_dev, node_st.st_ino) or os.stat("/proc/%d/ns/pid" % proc.pid).st_ino != EXPECTED_PIDNS:
                fail("test_process_identity")
            initial_namespace()
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + MAX_SECONDS
            while selector.get_map() or proc.poll() is None:
                left = deadline - time.monotonic()
                if left <= 0:
                    fail("test_timeout")
                for key, _ in selector.select(min(left, 1.0)):
                    block = os.read(key.fd, 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(block)
                    if len(output) > MAX_OUTPUT:
                        fail("test_output_bound")
            status = proc.wait(timeout=2)
        except BaseException as failure:
            cleanup_errors = []
            if proc.poll() is None:
                if pidfd is not None:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGTERM)
                        proc.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                            proc.wait(timeout=3)
                        except BaseException as error:
                            cleanup_errors.append(error)
                    except BaseException as error:
                        cleanup_errors.append(error)
                else:
                    try:
                        proc.wait(timeout=MAX_SECONDS)
                    except BaseException as error:
                        cleanup_errors.append(error)
            if pidfd is not None:
                try:
                    os.close(pidfd)
                    pidfd = None
                except BaseException as error:
                    cleanup_errors.append(error)
            if proc.stdout:
                try:
                    proc.stdout.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if selector is not None:
                try:
                    selector.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors:
                raise RuntimeError("receiver child cleanup, Wait, or descriptor settlement was uncertain: " + "; ".join(str(error) for error in cleanup_errors)) from failure
            raise
        else:
            cleanup_errors = []
            if pidfd is not None:
                try:
                    os.close(pidfd)
                    pidfd = None
                except BaseException as error:
                    cleanup_errors.append(error)
            if proc.stdout:
                try:
                    proc.stdout.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if selector is not None:
                try:
                    selector.close()
                except BaseException as error:
                    cleanup_errors.append(error)
            if cleanup_errors:
                fail("child_descriptor_settlement")
        text = output.decode("utf-8", "replace")
        if status != 0:
            fail("test_nonzero", failure_source_locations(text), failure_nested_diagnostic(text))
        events = []
        for line in text.splitlines():
            record = line.lstrip()
            if record.startswith("=== RUN"):
                match = re.fullmatch(r"=== RUN\s+(\S+)", record)
                if not match: fail("malformed_run_record")
                events.append(("RUN", match.group(1)))
            elif re.match(r"--- (?:PASS|SKIP|FAIL)(?:\s|:)", record):
                match = re.fullmatch(r"--- (PASS|SKIP|FAIL):\s+(\S+)\s+\((?:\d+(?:\.\d+)?s)\)", record)
                if not match: fail("malformed_result_record")
                events.append((match.group(1), match.group(2)))
        expected_events = [("RUN", "TestCheckpointObserverRouteComposedKernelFixture"), ("PASS", "TestCheckpointObserverRouteComposedKernelFixture")]
        if events != expected_events: fail("test_runpass_inventory")
        markers = ["CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS", "CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CLEANUP_PASS", "CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS", "CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS", "CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2", "CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY", "CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS"]
        positions = [text.find(marker) for marker in markers]
        if any(text.count(marker) != 1 for marker in markers) or positions != sorted(positions) or positions[0] < 0:
            fail("test_marker_inventory_or_order")
        exact_cleanup(ROOT, tmp_fd, held_tmp, upload_fd, held_root, files)
        sys.stdout.write(text)
        sys.stdout.write("\nREMOTE_OBSERVER_ROUTE_UPLOAD_CLEANUP_PASS\n")
    except BaseException as failure:
        cleanup_errors = []
        for fd, _ in files.values():
            try:
                os.close(fd)
            except BaseException as error:
                cleanup_errors.append(error)
        try:
            os.close(upload_fd)
        except BaseException as error:
            cleanup_errors.append(error)
        try:
            os.close(tmp_fd)
        except BaseException as error:
            cleanup_errors.append(error)
        if cleanup_errors:
            raise RuntimeError("receiver failure descriptor cleanup was uncertain") from failure
        raise
try:
    main()
except Exception as error:
    fail_exception(error)
`;

function shellQuote(value) { return `'${String(value).replaceAll("'", "'\\''")}'`; }

function runKernel() {
  if (process.platform !== 'win32') throw new Error('--kernel is fixed to the Windows cached toolchain and reviewed fixed-PVE receiver');
  fixedFile(fixedGo, 'cached Go 1.23.4 toolchain');
  fixedFile(fixedSSH, 'fixed OpenSSH client');
  fixedFile(fixedIdentity, 'fixed Proxmox identity');
  fixedFile(fixedKnownHosts, 'strict known-hosts file');
  const scratch = mkdtempSync(path.join(tmpdir(), 'checkpoint-observer-route-build-'));
  const rootInfo = lstatSync(scratch);
  const rootPin = { dev: rootInfo.dev, ino: rootInfo.ino };
  const pins = new Map();
  let confirmed = false;
  try {
    createCompilerTrees(scratch, rootPin, pins);
    const hostPath = path.join(scratch, 'checkpoint-observer-host.test');
    const nodePath = path.join(scratch, 'nodeagent.test');
    verifyCompilerRoots(scratch, pins);
    pins.set(path.basename(hostPath), compileLinuxTest(fixedGo, './internal/checkpointgpuobserver', 'checkpoint_container_kernel', hostPath));
    verifyCompilerRoots(scratch, pins);
    pins.set(path.basename(nodePath), compileLinuxTest(fixedGo, './internal/nodeagent', 'checkpoint_local_observer_kernel', nodePath));
    const hostBytes = readFileSync(hostPath);
    const nodeBytes = readFileSync(nodePath);
    const hostHash = createHash('sha256').update(hostBytes).digest('hex');
    const nodeHash = createHash('sha256').update(nodeBytes).digest('hex');
    if (hostBytes.length !== pins.get(path.basename(hostPath)).size || nodeBytes.length !== pins.get(path.basename(nodePath)).size ||
        hostBytes.length > 256 * 1024 * 1024 || nodeBytes.length > 256 * 1024 * 1024 ||
        hostBytes.subarray(0, 4).toString('hex') !== '7f454c46' || nodeBytes.subarray(0, 4).toString('hex') !== '7f454c46' ||
        hostBytes[4] !== 2 || nodeBytes[4] !== 2 || hostBytes[5] !== 1 || nodeBytes[5] !== 1 ||
        hostBytes.readUInt16LE(18) !== 62 || nodeBytes.readUInt16LE(18) !== 62) {
      throw new Error('cross-compiled fixture images are not bounded ELF64 amd64 binaries');
    }
    const receiver = `/usr/bin/python3 -c ${shellQuote(routeProxmoxReceiver)} ${hostBytes.length} ${hostHash} ${nodeBytes.length} ${nodeHash}`;
    const sshArgs = [
      '-F', 'none', '-T', '-oBatchMode=yes', '-oPreferredAuthentications=publickey', '-oPasswordAuthentication=no', '-oKbdInteractiveAuthentication=no',
      '-oStrictHostKeyChecking=yes', `-oUserKnownHostsFile=${fixedKnownHosts}`, '-oGlobalKnownHostsFile=none',
      '-oControlPath=none', '-oKnownHostsCommand=none', '-oIdentitiesOnly=yes', '-oIdentityAgent=none', '-i', fixedIdentity,
      '-p', '22', '-oHostName=10.0.0.3', '-oProxyCommand=none', '-oProxyJump=none', '-oClearAllForwardings=yes', '-oForwardAgent=no',
      '-oPermitLocalCommand=no', '-oRequestTTY=no', '-oControlMaster=no', '-oConnectTimeout=10',
      '-oServerAliveInterval=10', '-oServerAliveCountMax=2', 'root@10.0.0.3', receiver,
    ];
    const sshEnvironment = Object.fromEntries(['SystemRoot', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'HOME', 'PROGRAMDATA']
      .filter((key) => process.env[key]).map((key) => [key, process.env[key]]));
    const output = invoke(fixedSSH, sshArgs, { timeout: 210_000, maxBuffer: 3 * 1024 * 1024, env: sshEnvironment, receiverDiagnostic: true,
      input: Buffer.concat([hostBytes, nodeBytes]) }, 'fixed-PVE composed observer route receiver');
    if (output.split('REMOTE_OBSERVER_ROUTE_UPLOAD_CLEANUP_PASS').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_LOCAL_TREE_CUSTODY_CONTROLS_PASS').length !== 2 ||
        output.split('CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS').length !== 2 ||
        output.split('--- PASS: TestCheckpointObserverRouteComposedKernelFixture ').length !== 2 || /(?:^|\n)--- (?:FAIL|SKIP):/.test(output) ||
        output.indexOf('CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS') > output.indexOf('CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2') ||
        output.indexOf('CHECKPOINT_OBSERVER_ROUTE_PARENT_DEATH_REAP_PASS') < output.indexOf('CHECKPOINT_OBSERVER_ROUTE_LOCAL_SIGNED_BINDING_PASS') ||
        output.indexOf('CHECKPOINT_OBSERVER_ROUTE_HOST_SIGNED_JOIN_PASS_SYNTHETIC_ONLY count=2') > output.indexOf('CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY') ||
        output.indexOf('CHECKPOINT_OBSERVER_ROUTE_COMPOSED_KERNEL_PASS_SYNTHETIC_GPU_ONLY') > output.indexOf('CHECKPOINT_OBSERVER_ROUTE_OUTSIDE_SENTINEL_PRESERVED_PASS')) {
      throw new Error('fixed-PVE receiver did not attest exact composed fixture markers, RUN/PASS inventory and upload cleanup');
    }
    for (const name of ['go-cache', 'go-tmp']) pins.set(name, captureCompilerTree(path.join(scratch, name), pins.get(name)));
    confirmed = true;
  } finally {
    if (confirmed) removeExactScratch(scratch, rootPin, pins);
    else process.stderr.write('composed observer route failed; preserving exact private compiler workspace because cleanup is unconfirmed\n');
  }
}

if (mode === '--source') {
  sourceContracts();
  console.log('checkpoint observer route source verification passed');
  process.exit(0);
}
if (mode === '--unit') {
  sourceContracts();
  runUnit();
  console.log('checkpoint observer route unit verification passed');
  process.exit(0);
}
sourceContracts();
runKernel();
console.log('checkpoint observer route composed kernel verification passed');
