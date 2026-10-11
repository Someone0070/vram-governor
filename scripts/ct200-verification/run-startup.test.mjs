import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { __test } from './run-startup.mjs';
import { validateConfig } from './isolation-probe.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const receiver = path.join(here, 'run-startup.py');
const probePath = path.join(here, 'isolation-probe.mjs');
let probeErrorStack = '';
try { validateConfig({}); } catch (error) { probeErrorStack = error.stack; }
const probeSourceUrl = new URL('./isolation-probe.mjs', import.meta.url).href;
const fixedProbeErrorStack = probeErrorStack.replaceAll(probeSourceUrl, 'file:///source/scripts/ct200-verification/.probe.mjs');
assert.match(fixedProbeErrorStack,
  /^Error: isolation verification rejected\n    at fail \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:6:28\)\n    at object \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:9:[1-9][0-9]*\)\n    at (?:Module\.)?validateConfig \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:13:3\)\n/,
  'the pinned probe guard emits the expected fixed V8 error stack frames');
const uncaughtProbe = spawnSync(process.execPath, ['--input-type=module', '-e',
  "const {pathToFileURL}=await import('node:url');const p=await import(pathToFileURL(process.cwd()+'/scripts/ct200-verification/isolation-probe.mjs').href);p.validateConfig({});"], {
  cwd: path.resolve(here, '../..'), windowsHide: true, encoding: 'utf8', timeout: 5000, maxBuffer: 8192,
  env: { SystemRoot: process.env.SystemRoot, WINDIR: process.env.WINDIR },
});
assert.equal(uncaughtProbe.status, 1, 'the pure probe validator guard must throw when its fixed config shape is malformed');
assert.equal(uncaughtProbe.stdout, '', 'the pure probe validator negative must not emit a receipt');
const uncaughtProbeLines = uncaughtProbe.stderr.split(/\r?\n/);
const fixedUncaughtProbeLines = uncaughtProbeLines.map((line) => line.replaceAll(probeSourceUrl, 'file:///source/scripts/ct200-verification/.probe.mjs'));
assert.equal(fixedUncaughtProbeLines[0], 'file:///source/scripts/ct200-verification/.probe.mjs:6');
assert.equal(fixedUncaughtProbeLines[1], "const fail = () => { throw new Error('isolation verification rejected'); };");
assert.equal(fixedUncaughtProbeLines[2], `${' '.repeat(27)}^`);
assert.equal(fixedUncaughtProbeLines[4], 'Error: isolation verification rejected');
assert.match(fixedUncaughtProbeLines[5], /^    at fail \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:6:28\)$/);
assert.match(fixedUncaughtProbeLines[6], /^    at object \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:9:[1-9][0-9]*\)$/);
assert.match(fixedUncaughtProbeLines[7], /^    at (?:Module\.)?validateConfig \(file:\/\/\/source\/scripts\/ct200-verification\/\.probe\.mjs:13:3\)$/);
assert.match(fixedUncaughtProbeLines[8], /^    at file:\/\/\/.*\[eval[0-9]+\]:1:[1-9][0-9]*$/);
assert.match(fixedUncaughtProbeLines.filter(Boolean).at(-1), /^Node\.js v[0-9]+\.[0-9]+\.[0-9]+$/);
const PYTHON = 'C:/Program Files/Python38/python.exe';
const nonce = '0123456789abcdef0123456789abcdef';
const digest = 'a'.repeat(64);
const expected = { manifestSha256: digest, sourceManifestSha256: 'b'.repeat(64), startupFreezeSha256: digest };
const sha256 = (bytes) => {
  return createHash('sha256').update(bytes).digest('hex');
};

assert.equal(__test.canonicalWire({ z: 1, a: { y: 2, b: 3 } }).toString('ascii'), '{"a":{"b":3,"y":2},"z":1}');

function receipt(overrides = {}) {
  return {
    schema: 'ct200-startup-run-v1', status: 'passed', nonce,
    sourceManifestSha256: expected.sourceManifestSha256, bundleManifestSha256: expected.manifestSha256,
    startupFreezeSha256: digest,
    probeReceiptSha256: digest, unitOutputSha256: 'c'.repeat(64), testCount: 15,
    productionUnitsPreserved: true, ownedEffectsSettled: true, ...overrides,
  };
}

function framed(value, terminal = 'CT200_STARTUP_PASSED') {
  return Buffer.from(`${JSON.stringify(value)}\n${terminal}\n`, 'ascii');
}

assert.throws(() => __test.validateRunReceipt(framed(receipt()), 1, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt({ status: 'failed' })), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt({ nonce: 'f'.repeat(32) })), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt({ testCount: 16 })), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt({ ownedEffectsSettled: false })), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(Buffer.from(`${JSON.stringify(receipt())}\nCT200_STARTUP_FAILED\n`), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(Buffer.from(`${JSON.stringify(receipt())}\nCT200_STARTUP_PASSED\nextra\n`), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt({ unexpected: true })), 0, nonce, expected));
assert.throws(() => __test.validateRunReceipt(framed(receipt()), 0, nonce, { ...expected, manifestSha256: true }));

const capacityExpected = { ...expected, capacityFreezeSha256: __test.CAPACITY_FREEZE_SHA256 };
function capacityReceipt(overrides = {}) {
  return {
    schema: 'ct200-capacity-run-v1', mode: 'capacity', status: 'passed', nonce,
    sourceManifestSha256: capacityExpected.sourceManifestSha256, bundleManifestSha256: capacityExpected.manifestSha256,
    startupFreezeSha256: capacityExpected.startupFreezeSha256, capacityFreezeSha256: capacityExpected.capacityFreezeSha256,
    probeReceiptSha256: digest, capacityOutputSha256: sha256(Buffer.from(__test.CAPACITY_OUTPUT, 'utf8')),
    testCount: 82, packages: ['vram-governor/internal/api', 'vram-governor/internal/workloads'],
    productionUnitsPreserved: true, ownedEffectsSettled: true, ...overrides,
  };
}
const capacityReceiptBytes = (value = capacityReceipt(), terminal = 'CT200_CAPACITY_PASSED') => Buffer.from(`${JSON.stringify(value)}\n${terminal}\n`, 'ascii');
assert.equal(__test.validateCapacityRunReceipt(capacityReceiptBytes(), 0, nonce, capacityExpected).testCount, 82);
assert.throws(() => __test.validateRunReceipt(capacityReceiptBytes(), 0, nonce, expected),
  'startup parser rejects a capacity receipt');
for (const altered of [
  capacityReceipt({ mode: 'startup' }), capacityReceipt({ schema: 'ct200-startup-run-v1' }),
  capacityReceipt({ testCount: 15 }), capacityReceipt({ packages: ['vram-governor/internal/workloads', 'vram-governor/internal/api'] }),
  capacityReceipt({ capacityOutputSha256: 'f'.repeat(64) }), capacityReceipt({ capacityFreezeSha256: 'f'.repeat(64) }),
  capacityReceipt({ probeReceiptSha256: [digest] }), capacityReceipt({ probeReceiptSha256: {} }),
  capacityReceipt({ probeReceiptSha256: null }), capacityReceipt({ probeReceiptSha256: 7 }), capacityReceipt({ probeReceiptSha256: true }),
  capacityReceipt({ productionUnitsPreserved: false }), capacityReceipt({ extra: true }),
]) assert.throws(() => __test.validateCapacityRunReceipt(capacityReceiptBytes(altered), 0, nonce, capacityExpected));
assert.throws(() => __test.validateCapacityRunReceipt(capacityReceiptBytes(), 1, nonce, capacityExpected));
assert.throws(() => __test.validateCapacityRunReceipt(capacityReceiptBytes(), 0, nonce, { ...capacityExpected, capacityFreezeSha256: digest }));
assert.throws(() => __test.validateCapacityRunReceipt(capacityReceiptBytes(capacityReceipt(), 'CT200_STARTUP_PASSED'), 0, nonce, capacityExpected));

const config = {
  nonce, inputSha256: digest,
  outsideNamespaces: { pid: 'pid:[11]', mnt: 'mnt:[12]', net: 'net:[13]' },
};
const probe = {
  schema: 'lb-isolation-receipt-v1', nonce, inputSha256: digest, pid: 1,
  namespaces: { pid: 'pid:[21]', mnt: 'mnt:[22]', net: 'net:[23]' },
  limits: { 'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '100000 100000' },
};
assert.equal(__test.validateProbeReceipt(probe, config), probe);
assert.throws(() => __test.validateProbeReceipt(probe, { ...config, inputSha256: true }));
for (const mutate of [
  (p) => { p.pid = 2; },
  (p) => { p.namespaces.pid = config.outsideNamespaces.pid; },
  (p) => { p.limits['cpu.max'] = 'max 100000'; },
  (p) => { p.networkDenied = true; },
]) {
  const altered = structuredClone(probe);
  mutate(altered);
  assert.throws(() => __test.validateProbeReceipt(altered, config));
}

const unitNames = ['vram-governor-node-agent.service', 'llama-server.service', 'comfyui.service', 'comfy-harness.service', 'vram-governor-runtime-tunnel.service'];
const inventory = unitNames.map((Id) => ({ Id, LoadState: 'loaded', ActiveState: 'active', SubState: 'running', MainPID: '123', InvocationID: 'd'.repeat(32), MainPIDStartTime: 456 }));
const proof = { serviceExited: true, serviceCgroupEmpty: true, namespacesGone: true, ownedFixtureSettled: true };
assert.equal(__test.validateTerminalInventory(inventory, structuredClone(inventory), proof), true);
for (const alter of [
  (rows) => { rows[0].MainPID = '124'; },
  (rows) => { rows.pop(); },
  (rows) => { rows[1].InvocationID = 'not-an-id'; },
]) {
  const after = structuredClone(inventory);
  alter(after);
  assert.throws(() => __test.validateTerminalInventory(inventory, after, proof));
}
assert.throws(() => __test.validateTerminalInventory(inventory, inventory, { ...proof, namespacesGone: false }));
assert.throws(() => __test.validateTerminalInventory(inventory, [{ ...inventory[0], MainPID: 123 }, ...inventory.slice(1)], proof));

function materialsFixture() {
  const data = [
    ['modules/example.com/mod/@v/v1.0.0.info', Buffer.from('{}')],
    ['modules/example.com/mod/@v/v1.0.0.mod', Buffer.from('module example.com/mod\n')],
    ['modules/example.com/mod/@v/v1.0.0.zip', Buffer.from('zip')],
    ['modules/example.com/mod/@v/v1.0.0.ziphash', Buffer.from('h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=')],
    ['source/go.mod', Buffer.from('module fixture\n')],
    ['source/go.sum', Buffer.from('')],
    ['source/internal/nodeagent/a.go', Buffer.from('package nodeagent\n')],
    ['source/internal/nodeagent/b.go', Buffer.from('package nodeagent\n')],
    ['source/internal/nodeagent/c.go', Buffer.from('package nodeagent\n')],
    ['source/scripts/verify-checkpoint-startup-runtime.mjs', Buffer.from('fixture')],
  ];
  const files = data.map(([filePath, bytes]) => ({ path: filePath, bytes: bytes.length, sha256: sha256(bytes), base64: bytes.toString('base64') }));
  const rows = files.map(({ path: filePath, bytes, sha256: hash }) => ({ path: filePath, bytes, sha256: hash }));
  const sourceRows = rows.filter((row) => row.path.startsWith('source/')).map((row) => ({ ...row, path: row.path.slice('source/'.length) }));
  return {
    schema: 1, files, manifestSha256: sha256(Buffer.from(JSON.stringify(rows))),
    sourceManifestSha256: sha256(Buffer.from(JSON.stringify(sourceRows))), startupFreezeSha256: digest,
    sourceCount: 6, moduleCount: 1,
    moduleInventory: [{ modulePath: 'example.com/mod', version: 'v1.0.0', files: 1, bytes: 3, goHash1: 'h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=' }],
  };
}

function resealMaterialsBundle(bundle) {
  const rows = bundle.files.map(({ path: filePath, bytes, sha256: hash }) => ({ path: filePath, bytes, sha256: hash }));
  const sourceRows = rows.filter((row) => row.path.startsWith('source/')).map((row) => ({ ...row, path: row.path.slice('source/'.length) }));
  bundle.manifestSha256 = sha256(Buffer.from(JSON.stringify(rows)));
  bundle.sourceManifestSha256 = sha256(Buffer.from(JSON.stringify(sourceRows)));
  return bundle;
}

const goodBundle = materialsFixture();
assert.equal(__test.validateMaterialsBundle(goodBundle).fileCount, 10);
function capacityMaterialsFixture() {
  const data = [];
  for (const name of Object.keys(__test.CAPACITY_PINS)) data.push([`source/${name}`, fs.readFileSync(path.resolve(here, '../..', name))]);
  data.push(
    ['modules/example.com/mod/@v/v1.0.0.info', Buffer.from('{}')],
    ['modules/example.com/mod/@v/v1.0.0.mod', Buffer.from('module example.com/mod\n')],
    ['modules/example.com/mod/@v/v1.0.0.zip', Buffer.from('zip')],
    ['modules/example.com/mod/@v/v1.0.0.ziphash', Buffer.from('h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=\n')],
  );
  data.sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
  const files = data.map(([filePath, bytes]) => ({ path: filePath, bytes: bytes.length, sha256: sha256(bytes), base64: bytes.toString('base64') }));
  const rows = files.map(({ path: filePath, bytes, sha256: hash }) => ({ path: filePath, bytes, sha256: hash }));
  const sourceRows = rows.filter((row) => row.path.startsWith('source/')).map((row) => ({ ...row, path: row.path.slice('source/'.length) }));
  return {
    schema: 'ct200-capacity-materials-v1', mode: 'capacity', files,
    manifestSha256: sha256(Buffer.from(JSON.stringify(rows))), sourceManifestSha256: sha256(Buffer.from(JSON.stringify(sourceRows))),
    startupFreezeSha256: digest, capacityFreezeSha256: __test.CAPACITY_FREEZE_SHA256,
    sourceCount: sourceRows.length, moduleCount: 1,
    moduleInventory: [{ modulePath: 'example.com/mod', version: 'v1.0.0', files: 1, bytes: 3, goHash1: 'h1:EqbOt2cuTGyId7pp8AhTqIY7CSAiQyOQTkWYsau91oQ=' }],
  };
}
const goodCapacityBundle = capacityMaterialsFixture();
assert.equal(__test.validateMaterialsBundle(goodCapacityBundle, 'capacity').fileCount, 12,
  'capacity sender independently validates exact verifier plus all seven additional capacity pins');
assert.throws(() => __test.validateMaterialsBundle(goodCapacityBundle), /materials bundle schema failed/,
  'startup sender rejects capacity mode bundle');
for (const mutate of [
  (bundle) => { bundle.mode = 'startup'; },
  (bundle) => { bundle.capacityFreezeSha256 = 'f'.repeat(64); },
  (bundle) => { bundle.files.splice(bundle.files.findIndex((file) => file.path === 'source/internal/api/ws.go'), 1); },
]) {
  const altered = structuredClone(goodCapacityBundle);
  mutate(altered);
  assert.throws(() => __test.validateMaterialsBundle(altered, 'capacity'));
}
for (const name of Object.keys(__test.CAPACITY_PINS)) {
  const altered = structuredClone(goodCapacityBundle);
  const file = altered.files.find((entry) => entry.path === `source/${name}`);
  const wrong = Buffer.from('wrong pinned source');
  file.bytes = wrong.length; file.sha256 = sha256(wrong); file.base64 = wrong.toString('base64');
  resealMaterialsBundle(altered);
  assert.throws(() => __test.validateMaterialsBundle(altered, 'capacity'), undefined,
    `sender rejects altered independently pinned capacity source ${name}`);
  const missing = structuredClone(goodCapacityBundle);
  missing.files.splice(missing.files.findIndex((entry) => entry.path === `source/${name}`), 1);
  resealMaterialsBundle(missing);
  assert.throws(() => __test.validateMaterialsBundle(missing, 'capacity'), undefined,
    `sender rejects missing independently pinned capacity source ${name}`);
}
for (const field of ['manifestSha256', 'sourceManifestSha256', 'startupFreezeSha256']) {
  const bundle = structuredClone(goodBundle);
  bundle[field] = [bundle[field]];
  assert.throws(() => __test.validateMaterialsBundle(bundle), /materials bundle schema failed/);
}
{
  const bundle = structuredClone(goodBundle);
  bundle.files[0].sha256 = [bundle.files[0].sha256];
  assert.throws(() => __test.validateMaterialsBundle(bundle), /materials entry schema or ordering failed/);
}
for (const corrupt of [
  (bundle) => { bundle.files[0].base64 = '!!!!'; },
  (bundle) => { bundle.files[0].bytes += 1; },
  (bundle) => { bundle.files[0].sha256 = 'f'.repeat(64); },
  (bundle) => { bundle.manifestSha256 = 'f'.repeat(64); },
]) {
  const bundle = structuredClone(goodBundle);
  corrupt(bundle);
  assert.throws(() => __test.validateMaterialsBundle(bundle));
}
assert.throws(() => __test.validateMaterialsBundle({ schema: 1, files: [], manifestSha256: digest, sourceManifestSha256: digest, startupFreezeSha256: digest, sourceCount: 0, moduleCount: 0, moduleInventory: [] }));
{
  const bundle = structuredClone(goodBundle);
  const largeBytes = Buffer.alloc(1024 * 1024 + 1, 0xff);
  const entry = bundle.files.find((file) => file.path === 'modules/example.com/mod/@v/v1.0.0.zip');
  entry.bytes = largeBytes.length;
  entry.sha256 = sha256(largeBytes);
  entry.base64 = largeBytes.toString('base64');
  bundle.moduleInventory[0].bytes = largeBytes.length;
  resealMaterialsBundle(bundle);
  assert.equal(bundle.files.find((file) => file.path === entry.path).base64.endsWith('//8='), true);
  assert.equal(__test.validateMaterialsBundle(bundle).fileCount, 10, 'production sender must validate a real-size payload with recomputed digests');

  const malformed = (edit) => {
    const candidate = structuredClone(bundle);
    const payload = candidate.files.find((file) => file.path === entry.path);
    payload.base64 = edit(payload.base64);
    return candidate;
  };
  assert.throws(() => __test.validateMaterialsBundle(malformed((value) => `${value.slice(0, -2)}=${value.slice(-1)}`)), /materials base64 is not canonical/, 'large payload with excess padding must fail');
  assert.throws(() => __test.validateMaterialsBundle(malformed((value) => `${value.slice(0, 1024)}!${value.slice(1025)}`)), /materials base64 is not canonical/, 'large payload with an invalid character must fail');
  assert.throws(() => __test.validateMaterialsBundle(malformed((value) => value.slice(0, -1))), /materials base64 is not canonical/, 'large payload with an invalid encoded length must fail');
  assert.throws(() => __test.validateMaterialsBundle(malformed((value) => `${value.slice(0, -2)}9=`)), /materials payload authentication failed/, 'noncanonical base64 pad bits must fail canonical round-trip validation');
}
{
  const failureLine = Buffer.from('fixed startup supervisor failed stage=runtime category=controlled unit=preserved fixture=settled scratch=retained reason=service_result exception=reject frame=validation line=104 diagnostic=control\n', 'ascii');
  assert.deepEqual(__test.parseFailureEnvelope(failureLine), {
    stage: 'runtime', category: 'controlled', unit: 'preserved', fixture: 'settled', scratch: 'retained',
    reason: 'service_result', exception: 'reject', frame: 'validation', line: 104, diagnostic: 'control',
  }, 'sender accepts one exact finite receiver failure envelope');
  const cgroupFailureLine = Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=settled scratch=retained reason=cgroup_limit exception=reject frame=cgroup_validation line=1168 diagnostic=unclassified\n', 'ascii');
  assert.deepEqual(__test.parseFailureEnvelope(cgroupFailureLine), {
    stage: 'isolation', category: 'controlled', unit: 'preserved', fixture: 'settled', scratch: 'retained',
    reason: 'cgroup_limit', exception: 'reject', frame: 'cgroup_validation', line: 1168, diagnostic: 'unclassified',
  }, 'sender accepts the finite cgroup validation failure envelope');
  const mainMembershipFailureLine = Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=preserved scratch=retained reason=unit_main_membership exception=reject frame=unit_capture line=1648 diagnostic=unclassified\n', 'ascii');
  assert.equal(__test.parseFailureEnvelope(mainMembershipFailureLine).reason, 'unit_main_membership',
    'sender accepts the finite owned-unit main PID membership failure');
  for (const reason of ['unit_pid_gone', 'unit_pid']) {
    const pidFailureLine = Buffer.from(`fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=preserved scratch=retained reason=${reason} exception=reject frame=unit_capture line=1800 diagnostic=unclassified\n`, 'ascii');
    assert.equal(__test.parseFailureEnvelope(pidFailureLine).reason, reason,
      `sender accepts the finite ${reason} PID observation failure`);
  }
  const rootfsFailureLine = Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=settled scratch=retained reason=rootfs_custody exception=reject frame=isolation line=1810 diagnostic=unclassified\n', 'ascii');
  assert.equal(__test.parseFailureEnvelope(rootfsFailureLine).reason, 'rootfs_custody', 'sender accepts the finite private rootfs custody failure');
  const probeConfigFailureLine = Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=settled scratch=retained reason=service_result exception=reject frame=isolation line=1951 diagnostic=probe_config_missing\n', 'ascii');
  assert.equal(__test.parseFailureEnvelope(probeConfigFailureLine).diagnostic, 'probe_config_missing', 'sender accepts the finite structured missing probe configuration diagnostic');
  for (const diagnostic of ['probe_guard_error', 'probe_native_error']) {
    const line = Buffer.from(`fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=settled scratch=retained reason=service_result exception=reject frame=isolation line=1951 diagnostic=${diagnostic}\n`, 'ascii');
    assert.equal(__test.parseFailureEnvelope(line).diagnostic, diagnostic, `sender accepts the finite ${diagnostic} marker`);
  }
  const probeFailureLine = Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=settled scratch=retained reason=service_result exception=reject frame=isolation line=1784 diagnostic=probe_limits\n', 'ascii');
  assert.equal(__test.parseFailureEnvelope(probeFailureLine).diagnostic, 'probe_limits', 'sender accepts a finite precise probe diagnostic');
  for (const malformed of [
    Buffer.concat([failureLine, Buffer.from('extra\n')]),
    Buffer.alloc(513, 0x61),
    Buffer.concat([failureLine.subarray(0, failureLine.length - 1), Buffer.from([0xff, 0x0a])]),
    Buffer.from(failureLine.toString('ascii').replace('reason=service_result', 'reason=arbitrary_path')),
    Buffer.from(cgroupFailureLine.toString('ascii').replace('reason=cgroup_limit', 'reason=cgroup_unknown')),
    Buffer.from(mainMembershipFailureLine.toString('ascii').replace('reason=unit_main_membership', 'reason=unit_main_membership_unknown')),
    Buffer.from('fixed startup supervisor failed stage=isolation category=controlled unit=preserved fixture=preserved scratch=retained reason=unit_pid_gone_extra exception=reject frame=unit_capture line=1800 diagnostic=unclassified\n'),
    Buffer.from(cgroupFailureLine.toString('ascii').replace('frame=cgroup_validation', 'frame=cgroup_unknown')),
    Buffer.from(probeFailureLine.toString('ascii').replace('diagnostic=probe_limits', 'diagnostic=probe_unknown')),
    Buffer.from(failureLine.toString('ascii').replace('exception=reject', 'exception=unknown')),
    Buffer.from(failureLine.toString('ascii').replace('frame=validation', 'frame=unknown')),
    Buffer.from(failureLine.toString('ascii').replace('line=104', 'line=999999')),
    Buffer.from(failureLine.toString('ascii').replace('frame=validation line=104', 'frame=unlocated line=104')),
    Buffer.from(failureLine.toString('ascii').replace('frame=validation line=104', 'frame=validation line=0')),
    Buffer.from(failureLine.toString('ascii').replace('diagnostic=control', 'diagnostic=unknown')),
    Buffer.from(failureLine.toString('ascii').replace('stage=runtime', 'stage=arbitrary')),
    Buffer.from(failureLine.toString('ascii').replace(' category=', ' extra=x category=')),
  ]) {
    assert.equal(__test.parseFailureEnvelope(malformed), null, 'sender must discard malformed, extra, non-ASCII, oversized, or unknown enum envelopes');
  }
  assert.equal(__test.parseFailureEnvelope(Buffer.from('secret raw diagnostic\n')), null, 'sender must never surface raw receiver text');
}
assert.throws(() => __test.buildBootstrap(Buffer.from('')));
const receiverBytes = fs.readFileSync(receiver);
const receiverSource = receiverBytes.toString('utf8');
function assertPendingMainExitContract(source) {
  const monitor = source.slice(source.indexOf('def run_isolated('), source.indexOf('def cleanup_systemd_properties('));
  assert.ok(monitor.startsWith('def run_isolated('), 'monitor source is fixed and present');
  for (const required of [
    'main_exit_pending = False',
    'main_exit_phase_proven = False',
    'deferred_gone_members = set()',
    'or (main_exit_pending and not main_exit_phase_proven)',
    'service_monitor_poll_step(',
    'if terminal_observed:',
    'main_exit_pending = True',
    'track_active_unit_members(ordered_pids, current_context, SERVICE_PIDS, seen_pids,',
    'verify_cgroup(cgroup, unit, pids, (SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START))',
    'need(observed and child.returncode == 0 and stdout is not None and len(stdout) <= 8192, "service_result")',
    'need(production_before == production_after, "production_unit_changed")',
    'need(owned_unit_settled(fields, unit, empty), "service_cgroup_not_empty")',
    'need(current_start != original_start, "service_pid_survived")',
    'need(cleanup_outside_fixture(), "fixture_cleanup")',
  ]) assert.ok(monitor.includes(required), `pending-main-exit monitor must retain ${required}`);
  assert.ok(monitor.indexOf('verify_cgroup(cgroup, unit, pids, (SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START))') <
    monitor.indexOf('track_active_unit_members(ordered_pids, current_context, SERVICE_PIDS, seen_pids,') &&
    !monitor.includes('if child.poll() is None and time.monotonic() >= next_check:'),
  'the earlier active MainPID check stays before the later candidate catch and pending polls are not child-live gated');
  const pollStep = source.slice(source.indexOf('def service_monitor_poll_step('), source.indexOf('def capture_owned_unit('));
  const preowned = pollStep.slice(pollStep.indexOf('if not owned_started:'), pollStep.indexOf('pending_now ='));
  const owned = pollStep.slice(pollStep.indexOf('else:', pollStep.indexOf('if not owned_started:')), pollStep.indexOf('if not ((child_running'));
  assert.ok(preowned.includes('not pending and not phase_proven') && preowned.includes('type(known) is set and not known') &&
    preowned.includes('not deferred_gone') && preowned.includes('all(context[key] is None') &&
    preowned.includes('return True, props, False, False, False, now + 0.25') &&
    pollStep.indexOf('return True, props, False, False, False, now + 0.25') < pollStep.indexOf('phase = observe_phase'),
  'pre-owned activation reads cannot claim a pending or terminal phase');
  assert.ok(owned.includes('type(known) is dict') && owned.includes('context["cgroup"] == "/sys/fs/cgroup/system.slice/" + unit') &&
    owned.includes('known.get(context["main_pid"]) == context["main_start"]'),
  'terminal polling requires captured dictionary and bound unit/MainPID identity');
  assert.ok(pollStep.includes('child_running or (pending and not phase_proven)') &&
    pollStep.includes('props = read_properties(unit)') && pollStep.includes('phase = observe_phase(props, context)') &&
    pollStep.includes('account_main_exit_members(phase, context, known, seen, deferred_gone, _start, _confirm)') &&
    pollStep.includes('return True, props, True, pending_now, True, now + 0.25'),
  'the actual composed poll step schedules after child exit, obtains terminal proof, and accounts terminal members');
  const account = source.slice(source.indexOf('def account_main_exit_members('), source.indexOf('def service_monitor_poll_step('));
  assert.ok(account.includes('start_reader(pid)') && account.includes('record_unit_pid(pid, member_start, known, seen)') &&
    account.includes('confirm(pid, member_context, known)'), 'terminal member identities and missing-member proof remain mandatory');
  const activeMembers = source.slice(source.indexOf('def track_active_unit_members('), source.indexOf('def service_monitor_poll_step('));
  assert.ok(activeMembers.includes('candidate(main_pid)') && activeMembers.includes('pending_pid not in known') &&
    activeMembers.includes('deferred_gone.add(pending_pid)') &&
    activeMembers.includes('record_unit_pid(pending_pid, pending_start, known, seen)'),
  'active MainPID candidate accounts live sampled suffix members and defers only known ENOENT members');
  const validator = source.slice(source.indexOf('def validate_main_exit_fields('), source.indexOf('def observe_main_exit_phase('));
  assert.ok(validator.includes('fields["MainPID"] == "0"') &&
    validator.includes('fields["InvocationID"] == context["invocation"]') &&
    validator.includes('context["cgroup"] == "/sys/fs/cgroup" + fields["ControlGroup"]') &&
    validator.includes('fields["ActiveState"] in ("deactivating", "inactive")') &&
    validator.includes('ct200-startup-[a-f0-9]{32}\\.service'),
  'terminal phase is bound to the exact owned invocation and unit');
  const observer = source.slice(source.indexOf('def observe_main_exit_phase('), source.indexOf('def confirm_gone_non_main_after_main_exit('));
  assert.ok(observer.includes('context["main_pid"] not in pids') &&
    observer.includes('pids = _ops["read_pids"]') && observer.includes('validate_main_exit_fields(fields, context)') &&
    observer.includes('for _ in range(2):'), 'terminal phase requires repeated original-main absence and bounded cgroup membership');
  const gone = source.slice(source.indexOf('def confirm_gone_non_main_after_main_exit('), source.indexOf('def capture_owned_unit('));
  assert.ok(gone.includes('fresh != context["accounted_pids"]') && gone.includes('not fresh.issubset(set(known))') &&
    gone.includes('context["main_pid"] in fresh'), 'every terminal cgroup member must have an observed identity');
  assert.ok(monitor.includes('same_owned_unit(props_now, unit)') &&
    monitor.includes('"rootfs_id": SERVICE_ROOTFS_ID') && monitor.includes('"executable_id": SERVICE_EXEC_ID') &&
    monitor.includes('"argv_bytes": SERVICE_ARGV_BYTES') &&
    monitor.includes('SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START'),
  'the preceding active observation retains the immutable process, invocation, root, executable, and argv identity checks');
  const capture = source.slice(source.indexOf('def capture_owned_unit('), source.indexOf('def same_owned_unit('));
  assert.ok(capture.includes('SERVICE_PIDS = {}') && capture.includes('for pid in pids:') &&
    capture.includes('track_unit_pid(pid, main_pid, SERVICE_PIDS, provisional_context)') &&
    capture.includes('OWNED_UNIT_STARTED = True') &&
    capture.indexOf('SERVICE_PIDS = {}') < capture.indexOf('for pid in pids:') &&
    capture.indexOf('for pid in pids:') < capture.indexOf('OWNED_UNIT_STARTED = True'),
  'capture_owned_unit remains the sole empty-set to captured-dictionary transition');
}
assertPendingMainExitContract(receiverSource);
for (const [name, mutate] of [
  ['pending wait', (source) => source.replace('or (main_exit_pending and not main_exit_phase_proven)', 'or False')],
  ['launcher-independent terminal poll', (source) => source.replace('child_running or (pending and not phase_proven)', 'child_running')],
  ['terminal observation proof', (source) => source.replace('phase = observe_phase(props, context)', 'phase = None')],
  ['terminal member accounting', (source) => source.replace('account_main_exit_members(phase, context, known, seen, deferred_gone, _start, _confirm)', 'pass')],
  ['original MainPID candidate', (source) => source.replace('candidate(main_pid)', 'False')],
  ['deferred suffix disappearance bookkeeping', (source) => source.replace('deferred_gone.add(pending_pid)', 'pass')],
  ['pre-owned empty sentinel guard', (source) => source.replace('type(known) is set and not known', 'type(known) is set')],
  ['pre-owned pending exclusion', (source) => source.replace('not pending and not phase_proven', 'not phase_proven')],
  ['pre-owned unset identity guard', (source) => source.replace('all(context[key] is None for key in ("cgroup", "cgroup_id", "invocation", "main_pid", "main_start"))', 'True')],
  ['pre-owned activation-only return', (source) => source.replace('return True, props, False, False, False, now + 0.25', 'return True, props, True, True, True, now + 0.25')],
  ['owned captured dictionary guard', (source) => source.replace('type(known) is dict and set(context) == context_keys', 'set(context) == context_keys')],
  ['captured MainPID generation binding', (source) => source.replace('known.get(context["main_pid"]) == context["main_start"]', 'True')],
  ['capture dictionary transition', (source) => source.replace('SERVICE_PIDS = {}', 'SERVICE_PIDS = set()')],
  ['early active MainPID identity', (source) => source.replace('verify_cgroup(cgroup, unit, pids, (SERVICE_INVOCATION, SERVICE_MAIN_PID, SERVICE_MAIN_START))', 'verify_cgroup(cgroup, unit, pids)')],
  ['terminal MainPID proof', (source) => source.replace('fields["MainPID"] == "0" and fields["InvocationID"] == context["invocation"]', 'fields["MainPID"] == "321" and fields["InvocationID"] == context["invocation"]')],
  ['terminal cgroup binding', (source) => source.replace('context["cgroup"] == "/sys/fs/cgroup" + fields["ControlGroup"]', 'context["cgroup"] == fields["ControlGroup"]')],
  ['same-cgroup member accounting', (source) => source.replace('fresh != context["accounted_pids"]', 'False')],
  ['preceding process identity', (source) => source.replace('"argv_bytes": SERVICE_ARGV_BYTES', '"argv_bytes": b""')],
  ['service result gate', (source) => source.replace('need(observed and child.returncode == 0 and stdout is not None and len(stdout) <= 8192, "service_result")', 'pass')],
]) {
  assert.throws(() => assertPendingMainExitContract(mutate(receiverSource)), undefined,
    `source contract rejects removed ${name} proof`);
}
const probeBytes = fs.readFileSync(probePath);
assert.equal(receiverBytes.length, __test.RUNNER_SOURCE_BYTES, 'sender must pin the exact receiver byte count');
assert.match(__test.buildBootstrap(receiverBytes, probeBytes), new RegExp(__test.RUNNER_SOURCE_SHA256));
assert.equal(__test.SESSION_MS, 245000, 'default startup transport deadline remains unchanged');
assert.equal(__test.CAPACITY_SESSION_MS, 480000, 'capacity transport uses its separately bounded fixed deadline');
const capacityBootstrap = __test.buildBootstrap(receiverBytes, probeBytes, 'capacity');
assert.match(capacityBootstrap, /deadline=time\.monotonic\(\)\+470/);
assert.match(capacityBootstrap, /signal\.setitimer\(signal\.ITIMER_REAL,470\)/);
assert.match(capacityBootstrap, /'_capacity_mode':True/);
assert.match(__test.buildBootstrap(receiverBytes, probeBytes), /deadline=time\.monotonic\(\)\+235/);
assert.match(__test.buildBootstrap(receiverBytes, probeBytes), /'_capacity_mode':False/);
assert.throws(() => __test.buildBootstrap(receiverBytes, probeBytes, 'arbitrary'));
assert.throws(() => __test.buildBootstrap(receiverBytes, Buffer.concat([probeBytes, Buffer.from([0])])), 'sender must reject any changed probe bytes');

// Execute the actual production Python parser through its data-only fixture mode.
// It accepts only --verify, performs no filesystem writes or subprocess/network actions.
const python = spawnSync(PYTHON, ['-I', '-B', receiver, '--verify'], {
  cwd: path.resolve(here, '../..'), windowsHide: true, encoding: 'utf8', timeout: 10000,
  env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows' },
});
assert.equal(python.error, undefined, `Python parser fixture process failed to launch: ${python.error?.code ?? 'unknown'}`);
assert.equal(python.status, 0, 'production Python parser rejected exact valid/malformed go.mod fixtures');
const [pythonFixtureSummary, capacityWrapperLine, ...pythonExtra] = python.stdout.trimEnd().split('\n');
assert.equal(pythonFixtureSummary, 'startup receiver production parser fixtures passed nodeArchiveBytes=54108748');
assert.match(capacityWrapperLine, /^CAPACITY_WRAPPER_B64=[A-Za-z0-9+/]+={0,2}$/);
assert.deepEqual(pythonExtra, []);
assert.equal(python.stderr, '');
assert.equal(fs.existsSync(path.join(here, '__pycache__')), false, 'Python fixture mode must not create bytecode files');
// AST-extract the actual production bytes literal; never execute the generated wrapper.
const extractWrapper = [
  'import ast,pathlib,sys',
  'tree=ast.parse(pathlib.Path(sys.argv[1]).read_bytes())',
  'for node in ast.walk(tree):',
  " if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='wrapper' for target in node.targets) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,bytes):",
  '  sys.stdout.buffer.write(node.value.value); break',
  'else: raise SystemExit(1)',
].join('\n');
const wrapperResult = spawnSync(PYTHON, ['-I', '-B', '-c', extractWrapper, receiver], {
  cwd: path.resolve(here, '../..'), windowsHide: true, encoding: 'buffer', timeout: 10000,
  maxBuffer: 64 * 1024, env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows' },
});
assert.equal(wrapperResult.error, undefined, `fixed AST wrapper extraction failed: ${wrapperResult.error?.code ?? 'unknown'}`);
assert.equal(wrapperResult.status, 0, 'fixed Python AST extraction must return the actual production wrapper bytes');
assert.equal(wrapperResult.stderr.length, 0);
assert.ok(wrapperResult.stdout.length > 0 && wrapperResult.stdout.length < 64 * 1024, 'generated wrapper must remain bounded');
assert.ok(wrapperResult.stdout.every((byte) => byte <= 0x7f), 'generated wrapper syntax fixture must be ASCII');
const wrapperSource = wrapperResult.stdout.toString('ascii');
const capacityWrapperBytes = Buffer.from(capacityWrapperLine.slice('CAPACITY_WRAPPER_B64='.length), 'base64');
assert.equal(capacityWrapperBytes.toString('base64'), capacityWrapperLine.slice('CAPACITY_WRAPPER_B64='.length),
  'pure Python fixtures return one canonical static capacity wrapper');
assert.ok(capacityWrapperBytes.length > 0 && capacityWrapperBytes.length < 64 * 1024 && capacityWrapperBytes.every((byte) => byte <= 0x7f));
const capacityWrapperSource = capacityWrapperBytes.toString('ascii');
assert.match(capacityWrapperSource, /process\.argv=\[process\.execPath,'\/source\/scripts\/verify-runtime-profile-projection\.mjs','--unit'\];/);
assert.match(capacityWrapperSource, /process\.chdir\('\/source'\);if\(process\.cwd\(\)!=='\/source'\)throw new Error\('capacity verifier working directory'\);/);
assert.ok(capacityWrapperSource.indexOf("process.cwd()!=='/source'") < capacityWrapperSource.indexOf("await import(pathToFileURL('/source/scripts/verify-runtime-profile-projection.mjs')"));
assert.match(capacityWrapperSource, /testCount:82,packages:\["vram-governor\/internal\/api",\s*"vram-governor\/internal\/workloads"\]/);
assert.match(capacityWrapperSource, /CT200_CAPACITY_INNER_PASSED/);
assert.match(wrapperSource, /const probe = await probeModule\.probe\(\)\.catch\(reportProbeFailure\);/,
  'the generated wrapper attaches the fixed reporter only to the probe promise rejection');
const reportProbeFailureSource = /^function reportProbeFailure\(error\)\{[^\r\n]+\}$/m.exec(wrapperSource)?.[0];
assert.ok(reportProbeFailureSource, 'extract the actual generated closed probe-error marker handler');
const reportProbeFailure = (writeSync) => new Function('fs', `${reportProbeFailureSource}; return reportProbeFailure;`)({ writeSync });
const missingProbeConfig = Object.assign(new Error('native ENOENT fixture'), {
  code: 'ENOENT', syscall: 'open', path: '/probe-config.json',
});
const markerWrites = [];
const positiveReporter = reportProbeFailure((...args) => markerWrites.push(args));
assert.throws(() => positiveReporter(missingProbeConfig), (error) => error === missingProbeConfig,
  'generated handler must rethrow the original native Error object');
assert.deepEqual(markerWrites, [[2, 'CT200_PROBE_DIAGNOSTIC probe_config_missing\n', null, 'ascii']],
  'only the exact missing probe configuration tuple emits the fixed ASCII marker');
const guardRejection = new Error('isolation verification rejected');
const guardWrites = [];
assert.throws(() => reportProbeFailure((...args) => guardWrites.push(args))(guardRejection),
  (error) => error === guardRejection, 'guard marker handling preserves the original Error');
assert.deepEqual(guardWrites, [[2, 'CT200_PROBE_DIAGNOSTIC probe_guard_error\n', null, 'ascii']],
  'exact sentinel Error without code or syscall emits only the coarse guard marker');
const nativeProbeError = Object.assign(new Error('native I/O failure'), {
  code: 'EACCES', syscall: 'open', path: '/unrelated/native/path',
});
const nativeWrites = [];
assert.throws(() => reportProbeFailure((...args) => nativeWrites.push(args))(nativeProbeError),
  (error) => error === nativeProbeError, 'native marker handling preserves the original Error');
assert.deepEqual(nativeWrites, [[2, 'CT200_PROBE_DIAGNOSTIC probe_native_error\n', null, 'ascii']],
  'finite native errno and syscall emit a coarse marker without disclosing or attributing the path');
for (const altered of [
  Object.assign(new Error('wrong code'), { code: 'EXOTIC', syscall: 'open', path: '/probe-config.json' }),
  Object.assign(new Error('wrong syscall'), { code: 'ENOENT', syscall: 'stat', path: '/probe-config.json' }),
  Object.assign(new Error('ordinary error'), {}),
  Object.assign(new Error('code without syscall'), { code: 'ENOENT' }),
  Object.assign(new Error('unknown errno'), { code: 'EXOTIC', syscall: 'open' }),
  Object.assign(new Error('unknown syscall'), { code: 'EACCES', syscall: 'mystery' }),
  Object.assign(new Error('sentinel with structured code'), { message: 'isolation verification rejected', code: 'EACCES' }),
  Object.assign(new Error('sentinel with structured syscall'), { message: 'isolation verification rejected', syscall: 'open' }),
  { code: 'ENOENT', syscall: 'open', path: '/probe-config.json' },
  Object.defineProperty(new Error('throwing diagnostic field'), 'code', { get() { throw new Error('getter failed'); } }),
]) {
  const writes = [];
  const reporter = reportProbeFailure((...args) => writes.push(args));
  assert.throws(() => reporter(altered), (error) => error === altered,
    'generated handler must rethrow unrelated rejection values unchanged');
  assert.deepEqual(writes, [], 'unmatched and non-Error values must emit no marker');
}
const writeFailureReporter = reportProbeFailure(() => { throw new Error('diagnostic write failed'); });
assert.throws(() => writeFailureReporter(missingProbeConfig), (error) => error === missingProbeConfig,
  'diagnostic write failure must not replace the original probe rejection');
const checkWrapper = (source) => spawnSync(process.execPath, ['--check', '--input-type=module'], {
  cwd: path.resolve(here, '../..'), windowsHide: true, input: Buffer.from(source, 'ascii'), encoding: 'utf8',
  timeout: 10000, maxBuffer: 64 * 1024, env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows' },
});
const generatedSyntax = checkWrapper(wrapperSource);
assert.equal(generatedSyntax.error, undefined, `generated wrapper syntax check failed to launch: ${generatedSyntax.error?.code ?? 'unknown'}`);
assert.equal(generatedSyntax.status, 0, `actual generated wrapper must parse: ${generatedSyntax.stderr}`);
assert.equal(generatedSyntax.stdout, '');
const capacityGeneratedSyntax = checkWrapper(capacityWrapperSource);
assert.equal(capacityGeneratedSyntax.error, undefined, `capacity wrapper syntax check failed to launch: ${capacityGeneratedSyntax.error?.code ?? 'unknown'}`);
assert.equal(capacityGeneratedSyntax.status, 0, `actual generated capacity wrapper must parse: ${capacityGeneratedSyntax.stderr}`);
assert.equal(capacityGeneratedSyntax.stdout, '');
const escapedPair = '\\\\';
const escapedSingle = '\\';
const validBackslashLiteral = `value.includes('${escapedPair}')`;
assert.equal(wrapperSource.split(validBackslashLiteral).length - 1, 1, 'actual wrapper must contain exactly one correctly escaped backslash literal');
assert.ok(wrapperSource.includes("const marker = 'checkpoint startup runtime unit controls passed\\n';"), 'runtime marker newline escape must remain exact');
assert.ok(wrapperSource.includes("})+'\\nCT200_STARTUP_INNER_PASSED\\n');"), 'receipt newline escapes must remain exact');
const malformedWrapper = wrapperSource.replace(validBackslashLiteral, `value.includes('${escapedSingle}')`);
assert.notEqual(malformedWrapper, wrapperSource, 'negative fixture must reproduce the prior one-backslash generated source');
const malformedSyntax = checkWrapper(malformedWrapper);
assert.equal(malformedSyntax.error, undefined);
assert.notEqual(malformedSyntax.status, 0, 'Node syntax check must reject the former malformed generated backslash literal');
assert.match(malformedSyntax.stderr, /SyntaxError/);
const safePathFunction = /^function safePathText\(value\)\{[^\r\n]+\}$/m.exec(wrapperSource)?.[0];
assert.ok(safePathFunction, 'extract the actual generated pure path-text guard');
const pathGuardProgram = `${safePathFunction}\nif(!safePathText('modules/example.com/mod/@v/v1.0.0.zip')||safePathText(${JSON.stringify('bad\\name')})||safePathText(${JSON.stringify('bad\rname')})||safePathText(${JSON.stringify('bad\nname')})||safePathText(${JSON.stringify('bad\0name')}))process.exitCode=1;\n`;
const pathGuard = spawnSync(process.execPath, ['--input-type=module'], {
  cwd: path.resolve(here, '../..'), windowsHide: true, input: Buffer.from(pathGuardProgram, 'ascii'), encoding: 'utf8',
  timeout: 5000, maxBuffer: 4096, env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows' },
});
assert.equal(pathGuard.error, undefined, `isolated generated path guard failed to launch: ${pathGuard.error?.code ?? 'unknown'}`);
assert.equal(pathGuard.status, 0, 'actual generated path guard accepts safe text and rejects backslash/newline/NUL');
assert.equal(pathGuard.stdout, '');
assert.equal(pathGuard.stderr, '');
const invalid = spawnSync(PYTHON, ['-I', '-B', receiver, '--not-verify'], {
  cwd: path.resolve(here, '../..'), windowsHide: true, encoding: 'utf8', timeout: 10000,
  env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows' },
});
assert.equal(invalid.error, undefined, `fixed Python invalid-usage fixture failed to launch: ${invalid.error?.code ?? 'unknown'}`);
assert.equal(invalid.status, 2, 'Python receiver must reject all non-fixed CLI modes');
assert.equal(invalid.stdout, '');
assert.equal(invalid.stderr, '');
assert.equal(fs.existsSync(path.join(here, '__pycache__')), false, 'invalid usage must not create bytecode files');

process.stdout.write('isolated startup transaction controls passed\n');
